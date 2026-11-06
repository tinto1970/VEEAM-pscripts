// VeeamLogAnonymizer engine.
// Written in C# 5 syntax so that it compiles with Add-Type both on
// Windows PowerShell 5.1 (.NET Framework) and on PowerShell 7+ (.NET).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace VeeamLogAnonymizer
{
    public sealed class MapEntry
    {
        public string Category;
        public string Original;
        public string Fake;
        public bool Bare = true;     // matched as a standalone term (not only inside an FQDN)
        public long Hits;
        public string Source;
    }

    public sealed class Candidate
    {
        public string Value;
        public string Category;
        public string Source;
        public long Count;
    }

    public sealed class LeakInfo
    {
        public string Original;
        public string Category;
        public long Count;
        public long WholeWord;     // occurrences delimited by non-alphanumeric chars (real leaks)
        public long Partial;       // occurrences inside a longer word (often false positives)
        public string WholeSample;
        public string FirstFile;
        public string Sample;
    }

    public sealed class FileText
    {
        public string Text;
        public Encoding Encoding;
        public bool Binary;
    }

    internal sealed class TrieNode
    {
        public Dictionary<char, TrieNode> Next;
        public MapEntry Entry;
        public MapEntry Any;     // some entry whose key passes through this node (used for truncated names)
        public int AnyCount;     // how many distinct entries pass through this node
    }

    internal sealed class Trie
    {
        public readonly TrieNode Root = new TrieNode();
        public int Count;

        public void Add(string key, MapEntry e)
        {
            if (string.IsNullOrEmpty(key)) return;
            TrieNode n = Root;
            foreach (char ch in key)
            {
                char c = char.ToLowerInvariant(ch);
                if (n.Next == null) n.Next = new Dictionary<char, TrieNode>();
                TrieNode nx;
                if (!n.Next.TryGetValue(c, out nx)) { nx = new TrieNode(); n.Next[c] = nx; }
                n = nx;
                if (n.Any == null) { n.Any = e; n.AnyCount = 1; }
                else if (!ReferenceEquals(n.Any, e) && n.Any.Fake != e.Fake) n.AnyCount++;
            }
            if (n.Entry == null) { Count++; n.Entry = e; }
        }
    }

    internal sealed class IpStat
    {
        public long Total;
        public long Strong;
        public long Version;
        public long VersionWord;
    }

    public sealed class Engine
    {
        // ------------------------------------------------------------------ configuration
        public readonly HashSet<string> KeepTerms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> WhitelistDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool AnonymizePublicIPs = true;
        public bool AnonymizeMac = true;
        public bool AnonymizeIPv6 = true;
        public bool AnonymizeBase64 = true;
        public int MinBareTermLength = 3;

        // ------------------------------------------------------------------ state
        private readonly Dictionary<string, MapEntry> _terms = new Dictionary<string, MapEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, MapEntry> _fixed = new Dictionary<string, MapEntry>(StringComparer.OrdinalIgnoreCase); // IP, MAC, SID, IPv6
        private readonly Dictionary<string, Candidate> _cand = new Dictionary<string, Candidate>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, long> _fqdnTokens = new Dictionary<string, long>(StringComparer.Ordinal);
        private readonly HashSet<string> _strongFqdn = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _suffixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _inventoryPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, IpStat> _ip = new Dictionary<string, IpStat>();
        private readonly Dictionary<string, int> _counters = new Dictionary<string, int>();
        private readonly HashSet<string> _usedFakes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, long> _keptIpLike = new Dictionary<string, long>();
        private readonly Dictionary<string, long> _stats = new Dictionary<string, long>();
        private Trie _trie;
        private bool _finalized;

        public Engine()
        {
            foreach (string s in DefaultKeep) KeepTerms.Add(s);
            foreach (string s in DefaultWhitelistDomains) WhitelistDomains.Add(s);
        }

        // ================================================================== static lists
        private static readonly string[] DefaultKeep = {
            "localhost","localdomain","administrator","administrators","admin","system","root","guest","anonymous",
            "everyone","users","user","network service","local service","nt authority","builtin","nt service",
            "postgres","postgresql","veeam","current","default","defaultaccount","wdagutilityaccount","sa","nobody",
            "daemon","null","none","true","false","unknown","n/a","vsphere.local","vsphere","esxi","vcenter",
            "veeambackup","veeamsql2017","veeamsql2016","veeamsql2012","mssqlserver","sqlexpress","local","host",
            "server","client","proxy","agent","backup","repository","target","source","gateway","node","cluster",
            "datacenter","datacenters","vm","vms","domain","workgroup","service","window manager","font driver host",
            "iis apppool","public","all users","default user","sqltelemetry","mssqlfdlauncher","mssqllaunchpad",
            "systemprofile","localsystem","networkservice","localservice","dwm-1","umfd-0","umfd-1","dwm-2",
            "test","demo","example","sql","web","app","db","dc","fs","mail","smtp","www","ftp","ns1","ns2"
        };

        private static readonly string[] DefaultWhitelistDomains = {
            "veeam.com","microsoft.com","windows.com","windows.net","windowsupdate.com","microsoftonline.com",
            "sharepoint.com","sharepoint.us","onmicrosoft.com","onmicrosoft.us","outlook.com","microsoft365.com","teams.microsoft.com",
            "azure.com","azure.net","azureedge.net","msftconnecttest.com","msocsp.com","live.com","office.com",
            "office365.com","amazonaws.com","aws.amazon.com","amazon.com","wasabisys.com","digicert.com",
            "entrust.net","verisign.com","globalsign.com","globalsign.net","letsencrypt.org","sectigo.com",
            "usertrust.com","comodoca.com","godaddy.com","w3.org","ietf.org","xmlsoap.org","openxmlformats.org",
            "google.com","googleapis.com","gstatic.com","vmware.com","broadcom.com","nutanix.com","proxmox.com",
            "redhat.com","ubuntu.com","canonical.com","debian.org","rockylinux.org","centos.org","fedoraproject.org",
            "postgresql.org","oracle.com","mongodb.com","kasten.io","k8s.io","kubernetes.io","docker.io","docker.com",
            "github.com","githubusercontent.com","nuget.org","cloudflare.com","backblazeb2.com","ibm.com","hpe.com",
            "dell.com","netapp.com","purestorage.com","vsphere.local","example.com","example.org","example.net","asp.net","ado.net","vb.net","aka.ms","tempuri.org","format.com","mode.com","more.com","chcp.com",
            "tree.com","etfsboot.com","command.com","edit.com","debug.com","win.com","diskcopy.com","diskcomp.com",
            "graftabl.com","keyb.com","kb16.com","loadfix.com","mem.com","print.com","sys.com","mscorlib.com",
            "schemas.microsoft.com","apache.org","java.com","mozilla.org","python.org","npmjs.org","jquery.com"
        };

        private static readonly HashSet<string> PublicTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "com","net","org","edu","gov","mil","int","it","eu","de","fr","uk","co","ch","at","be","nl","es","pt",
            "se","no","dk","fi","pl","cz","sk","hu","ro","gr","ie","lu","si","hr","io","cloud","biz","info","us",
            "ca","au","nz","jp","cn","ru","br","in","me","tv","online","site","tech","app","dev","ai","xyz","pro",
            "sm","va","li","mc","mt","cy","ee","lv","lt","bg","rs","ua","tr","il","za","mx","ar","sg","hk","tw","kr"
        };

        private static readonly HashSet<string> InternalTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "local","lan","internal","corp","intra","intranet","home","localdomain","lab","priv","private","loc"
        };

        // TLDs kept verbatim when building fake FQDNs (not identifying by themselves)
        private static readonly HashSet<string> KeepTldInFake = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "local","lan","internal","corp","intra","intranet","home","localdomain","lab","com","net","org","it","eu",
            "de","fr","uk","ch","io","cloud","info","biz","ad","priv","private","loc"
        };

        private static readonly HashSet<string> CodePrefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "system","microsoft","grpc","windows","veeam","newtonsoft","nlog","log4net","npgsql","mono","netstandard",
            "mscorlib","google","amazon","aws","azure","java","javax","org","com","net","io","std","boost","nqn","iqn",
            "schemas","xmlns","app","api","v1","v2","v3","yarp","polly","serilog","castle","autofac","protobuf",
            "kestrel","aspnetcore","mvc","entityframework","efcore","dotnet","runtime","vmware","vim","vim25","sdk"
        };

        private static readonly HashSet<string> FileExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "log","txt","dll","exe","xml","json","config","cfg","ini","vbk","vib","vrb","vbm","vmdk","vmx","vhd",
            "vhdx","avhdx","iso","zip","gz","cab","msi","ps1","psm1","sys","tmp","bak","dat","db","mdf","ldf","csv",
            "html","htm","js","css","png","jpg","pdf","md","sh","py","yaml","yml","conf","cs","h","cpp","so","pem",
            "crt","cer","pfx","key","nvram","vmsd","vmxf","vswp","lck","etl","evtx","blob","meta","bin","old","wrn",
            "lnk","rdp","bat","cmd","vbs","sql","bk","vacm","vsb","vlb","vsm","vom","flr","part","chk","idx"
        };

        // generic words that must never become standalone terms
        private static readonly HashSet<string> Stop = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "localhost","local","true","false","none","null","nil","unknown","undefined","default","empty","any",
            "all","auto","automatic","yes","no","ok","error","warning","info","debug","trace","failed","success",
            "port","host","hosts","server","servers","client","proxy","agent","service","services","target","source",
            "backup","backups","replica","repository","gateway","node","nodes","cluster","datacenter","vm","vms",
            "master","primary","secondary","current","new","old","the","an","is","to","from","for","with","by",
            "on","in","at","of","and","or","not","system","admin","administrator","root","guest","user","users",
            "everyone","anonymous","network","internet","domain","workgroup","veeam","vbr","sql","postgres","mssql",
            "microsoft","windows","linux","vmware","hyperv","hyper-v","vcenter","esxi","esx","nas","san","smb","nfs",
            "cifs","s3","aws","azure","gcp","wasabi","amazon","google","kasten","nutanix","proxmox","pve","ahv",
            "xen","kvm","object","objects","storage","disk","disks","volume","volumes","file","files","folder",
            "path","name","id","type","mode","state","status","value","values","key","keys","item","items","task",
            "tasks","job","jobs","session","sessions","machine","computer","guest","host-name","hostname","tcp",
            "udp","http","https","ssh","rpc","wmi","api","rest","grpc","net","dns","ip","ipv4","ipv6","mac","vlan",
            "dhcp","static","dynamic","primary","inventory","folder","vapp","template","templates","resource",
            "pool","resources","datastore","datastores","network","networks","snapshot","snapshots","console",
            "shell","main","test","lab","demo","prod","production","dev","development","staging","home","office",
            "public","private","shared","common","global","internal","external","manual","manually","added",
            "protection","group","groups","policy","policies","plugin","plugins","platform","appliance","appliances",
            "infra","infrastructure","cloud","tenant","provider","vcd","vsphere","mount","transport","catalog",
            "indexing","index","collector","collectors","processing","unavailable","available","online","offline",
            "start","started","stop","stopped","running","completed","success","warning","idle","pending","dc",
            "station","lan","corp","intra","ad","mail","smtp","www","web","app","db","fs","ftp","ns1","ns2","sa",
            "this","that","these","those","it","its","be","are","was","were","has","have","had","can","will",
            "may","must","should","would","could","did","does","do","done","get","set","put","post","delete",
            "patch","head","options","entry","entries","list","table","row","rows","column","columns","data",
            "info","information","details","detail","message","messages","result","results","response","request",
            "requests","tenantid","userid","username","login","logon","password","credential","credentials","token",
            "certificate","certificates","thumbprint","subject","issuer","license","licenses","version","versions",
            "build","release","module","component","components","update","updates","upgrade","installer","setup",
            "self","me","my","our","your","their","his","her","them","they","we","you","he","she","one","two",
            "three","first","last","next","previous","prev","other","others","some","each","every","both","either",
            "neither","via","per","than","then","else","when","where","while","what","which","who","why","how",
            "linux-agent","windows-agent","tape","cdp","replication","failover","failback","restore","recovery",
            "instant","sure","surebackup","verification","health","check","retention","cleanup","merge","compact",
            "synthetic","full","incremental","increment","active","passive","standby","tasks","worker","workers",
            "nt","authority","builtin","iis","apppool","msa","gmsa","temp","tmp","sub","smb1","smb2","smb3","nfs3",
            "nfs4","nfs41","platform9","pipe","interactive","non-interactive","string","disabled","enabled","ontap",
            "replicas","vaults","libraries","entrust","digicert","verisign","globalsign","sectigo","letsencrypt",
            "wms","won","hasn","primary-node","secondary-node","vergeos","ref","uuid","vitype","count","immutable",
            "region","bucket","buckets","container","account","accounts","tenant","tenants","credentials","cloud",
            "font","window","transform","transforms","model","msdb","master","tempdb","resource","mssqlsystemresource","ipv4-only","ipv6-only","x64","x86","amd64","arm64","win32","win64","utf-8","utf8","iso-8859-1"
        };

        private static readonly HashSet<string> StopShares = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "admin$","ipc$","print$","root","pipe","sysvol","netlogon","globalroot","wsl$","wsl.localhost","users",
            "c$","d$","e$","f$","g$","h$","n$","z$","share","shares","backup","backups","veeam","tsclient","cimv2"
        };

        private static readonly Regex RxGuid = new Regex(@"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$", RegexOptions.Compiled);
        private static readonly Regex RxMoref = new Regex(@"^(?:host|vm|datastore|domain|group|resgroup|network|dvportgroup|dvs|folder|datacenter|cluster|vapp|alarm|task|session|snapshot|vmgroup|storagepod|ha-host)-\d+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex RxLabel = new Regex(@"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", RegexOptions.Compiled);
        private static readonly Regex RxHexish = new Regex(@"^[0-9a-fA-F]{12,}$", RegexOptions.Compiled);
        private static readonly Regex RxCamel = new Regex(@"[a-z][A-Z]|^[A-Z][a-z]+[A-Z]", RegexOptions.Compiled);
        private static readonly Regex RxNumericish = new Regex(@"^[\d._:-]+$", RegexOptions.Compiled);

        // ================================================================== discovery regexes
        private const RegexOptions RO = RegexOptions.Compiled | RegexOptions.CultureInvariant;
        private const RegexOptions ROI = RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;

        private static readonly Regex DxUrl = new Regex(@"\b(?:https?|wss?|ftps?|ldaps?|smb|nfs|net\.tcp|tcp|grpc|sftp|ssh)://(?:(?<u>[^@/\s:'""]+)(?::(?<p>[^@/\s'""]*))?@)?(?<h>[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])(?=[:/\s'""\]>)?;,&]|$)", ROI);
        private static readonly Regex DxUnc = new Regex(@"(?<![\w\\:])\\{2,4}(?<h>[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9])\\{1,2}(?<s>[^\\/\s'""\]\[:*?<>|]{1,80})", RO);
        private static readonly Regex DxHostKw = new Regex(@"\b(?:dns\s?name|fqdn|host\s?name|computer\s?name|machine\s?name|server\s?name|host|server|proxy|gateway|node|endpoint|mount\s?server|repository\s?server|peer|computer|machine)\b(?:\s*(?:=|:|is|name))?\s*(?:&quot;|&amp;quot;|['""\[(<])\s*(?<h>[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9])\s*(?::\d{1,5})?\s*(?:&quot;|&amp;quot;|['""\])>])", ROI);
        private static readonly Regex DxHostKwFqdn = new Regex(@"\b(?:host|server|computer|machine|fqdn|dns\s?name|hostname|host\s?name|address)\b\s*(?:name)?\s*[:=]?\s*(?<h>[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+)\b", ROI);
        private static readonly Regex DxHostPort = new Regex(@"(?:[\['""(]|&quot;)(?<h>[A-Za-z][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*):(?<p>\d{2,5})(?=[\]'"")\s,;/&]|$)", RO);
        private static readonly Regex DxCn = new Regex(@"\b(?:CN|cn)=(?<h>[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9])(?=[,/\s'""\]>;&]|$)", RO);
        private static readonly Regex DxIqn = new Regex(@"\biqn\.\d{4}-\d{2}\.[A-Za-z0-9.-]+:(?<h>[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])", ROI);
        private static readonly Regex DxDomUser = new Regex(@"\b(?:user(?:\s?name)?|account|owner|login|logon|credentials?|run\s?as|principal|guest\s?user|host\s?user|identity|sid\s?owner|by)\b\s*(?:=|:|is)?\s*['""\[(]?\s*(?<d>[A-Za-z0-9][A-Za-z0-9.-]{0,62})\\{1,2}(?<u>[A-Za-z0-9][\w.$-]{0,63})", ROI);
        private static readonly Regex DxUser = new Regex(@"\b(?:user(?:\s?name)?|login|logon\s?name|guest\s?user|host\s?user|run\s?as|owner|account\s?name)\b(?:\s*[:=]\s*['""\[(]?|\s*['""\[(])\s*(?<u>[A-Za-z0-9][\w.$-]{0,63})(?:@(?<f>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+))?", ROI);
        private static readonly Regex DxHome = new Regex(@"(?<![\w.])/(?:home|Users)/(?<u>[A-Za-z_][A-Za-z0-9_.-]{0,31})(?=/|\s|'|""|\]|$)", RO);
        private static readonly Regex DxWinProfile = new Regex(@"\b[A-Za-z]:\\{1,2}(?:Users|Documents and Settings)\\{1,2}(?<u>[^\\/:*?""<>|\r\n\t]{1,64}?)(?=\\|/|['""\s\]]|$)", ROI);
        private static readonly Regex DxEmail = new Regex(@"(?<![\w.%+-])(?<u>[A-Za-z0-9._%+-]{1,64})@(?<f>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b", RO);
        private static readonly Regex DxJob = new Regex(@"\bjob\b(?:\s*name)?(?:\s*[:=]\s*|\s+)(?:['""\[])(?<j>[^'""\]\[\r\n]{2,120})['""\]]", ROI);
        private static readonly Regex DxJobName = new Regex(@"\bJobName\s*[=:]\s*['""\[]?(?<j>[^'""\],;\r\n]{2,120})", ROI);
        private static readonly Regex DxRepoName = new Regex(@"\b(?:RepositoryName|RepoName|BackupRepositoryName)\s*[=:]\s*['""\[]?(?<r>[^'""\],;\r\n]{2,120})", ROI);
        private static readonly Regex DxRepoQ = new Regex(@"\brepository\b(?:\s*name)?(?:\s*[:=]\s*|\s+)(?:['""\[])(?<r>[^'""\]\[\r\n]{2,120})['""\]]", ROI);
        private static readonly Regex DxRepoGuid = new Regex(@"\b(?:repository|repo|extent)\s+(?<r>[^\s()'""\[\]]{2,80})\s?\([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-", ROI);
        private static readonly Regex DxBucket = new Regex(@"\bbucket(?:\s?name)?\b(?:\s*[:=]\s*['""\[(]?|\s*['""\[(])\s*(?<b>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?=['""\])\s,;/]|$)", ROI);
        private static readonly Regex DxS3Vhost = new Regex(@"\b(?<b>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-](?:[a-z0-9-]+\.)*(?:amazonaws\.com|wasabisys\.com|backblazeb2\.com)", ROI);
        private static readonly Regex DxAzureAcct = new Regex(@"\b(?<a>[a-z0-9]{3,24})\.(?:blob|queue|table|file|dfs)\.core\.(?:windows\.net|chinacloudapi\.cn|usgovcloudapi\.net)", ROI);
        private static readonly Regex DxAzureAcct2 = new Regex(@"\b(?:AccountName|StorageAccount(?:Name)?)\s*[=:]\s*['""\[]?(?<a>[a-z0-9]{3,24})\b", ROI);
        private static readonly Regex DxAccessKey = new Regex(@"\b(?:access\s?key(?:\s?id)?|accesskeyid|aws_access_key_id|key\s?id|credentials)\b\s*(?:[:=]\s*)?['""\[(]?\s*(?<k>[A-Za-z0-9]{16,128})(?=['""\])\s,;]|$)", ROI);
        private static readonly Regex DxAwsKey = new Regex(@"\b(?<k>(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16})\b", RO);
        private static readonly Regex DxSecret = new Regex(@"\b(?:secret(?:\s?access)?\s?key|secret|password|passwd|pwd|account\s?key|shared\s?key|sas\s?token|api\s?key|client\s?secret|private\s?key)\b[""']?\s*[:=]\s*['""]?(?<s>[^'""\s,;}\]]{4,512})", ROI);
        private static readonly Regex DxBearer = new Regex(@"\b(?:Bearer|Basic)\s+(?<s>[A-Za-z0-9._~+/=-]{16,})", RO);
        private static readonly Regex DxJwt = new Regex(@"\b(?<s>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})", RO);
        private static readonly Regex DxObject = new Regex(@"\b(?:vm|virtual\s?machine|object|guest|workload|vm\s?name|object\s?name)\b(?:\s*name)?(?:\s*[:=]\s*|\s+)(?:['""\[])(?<o>[^'""\]\[\r\n]{2,100})['""\]]", ROI);
        // VMware convention: "[datastore] vmname/vmname.vmx" or "[datastore] vmname/vmname_1.vmdk"
        private static readonly Regex DxVmx = new Regex(@"\[(?<ds>[^\]\r\n\[]{1,80})\]\s?(?<o>[^/\r\n\[\]]{1,100})/(?<f>[^/\r\n'""\]]{1,200}?)\.(?:vmx|vmdk|nvram|vmsd|vmxf|vmtx)\b", ROI);
        private static readonly Regex DxDatacenter = new Regex(@"\bdatacenter(?:InventoryPath|Name)?\s*[=:]\s*(?:['""]|&quot;)(?<i>[^'""&\r\n]{1,100})(?:['""]|&quot;)", ROI);
        private static readonly Regex DxInvPath = new Regex(@"\b(?:Path|Location|InventoryPath)\s*=\s*(?:""|&quot;)(?<p>[^""&\r\n]{3,400})(?:""|&quot;)", ROI);
        private static readonly Regex DxInvPath2 = new Regex(@"<(?:Location|DirPath)>(?<p>[^<\r\n]{3,400})</", ROI);
        private static readonly Regex DxNameRef = new Regex(@"\bname\s*[:=]?\s*'(?<n>[^'\r\n]{1,100})',\s*ref\s*[:=]?\s*'(?<t>[a-zA-Z]+)-\d+'", ROI);
        private static readonly Regex DxVmColon = new Regex(@"\bVM:\s(?<o>[A-Za-z0-9][\w.-]{1,62}),\s[0-9a-fA-F]{8}-", RO);
        private static readonly Regex DxAnyDomUser = new Regex(@"(?<![\w\\.$-])(?<d>[A-Za-z0-9][A-Za-z0-9.-]{0,62})\\{1,2}(?<u>[A-Za-z][\w.$-]{0,63})(?![\w\\/$])", RO);
        private readonly Dictionary<string, HashSet<string>> _domUsers = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Regex DxFqdnToken =new Regex(@"(?<![\w.@-])(?<f>[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63}){1,10})(?![\w-]|\.[\w-])", RO);
        private static readonly Regex DxSmtp = new Regex(@"\b(?:smtp\s?server|mail\s?server|smtp)\b\s*[:=]?\s*['""\[(]?(?<h>[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])", ROI);

        // ---- categories listed in Veeam KB2462 (sensitive data in logs)
        // certificate thumbprints, SSL fingerprints, SSH host key fingerprints
        private static readonly Regex DxThumb = new Regex(@"(?:thumb|finger)\s?print\w{0,12}(?:&(?:amp;)*quot;|[^A-Za-z0-9\r\n]){0,24}(?:value(?:&(?:amp;)*quot;|[^A-Za-z0-9\r\n]){1,16}|is\s|(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d{3}|SHA256|SHA1|MD5)[:\s]\s?)?(?<v>[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){15,63}|[0-9A-Fa-f]{32,128}|[A-Za-z0-9+/]{43}=?)(?![A-Za-z0-9+/=:-])", ROI);
        private static readonly Regex DxSshKeyFp = new Regex(@"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d{3})\s(?:SHA256:)?(?<v>[A-Za-z0-9+/]{43}=?)(?![A-Za-z0-9+/=])", RO);
        // database names: SQL Server, PostgreSQL, Oracle, MongoDB, SAP HANA, Exchange, SharePoint
        private static readonly Regex DxDbQ = new Regex(@"\b(?:DbName|DatabaseName|Database|db_?name|LogicalName|ContentDatabase|MailboxDatabase|ReplicaSet(?:Name)?|replSet|OracleSid|ORACLE_SID|GlobalName|global_name|OracleHomeName|ORACLE_HOME_NAME|TenantDatabase|PdbName|CdbName|CollectionName)\s*[=:]\s*(?:&(?:amp;)*quot;|[""'\[])(?<d>[A-Za-z_][\w$#.-]{0,127}?)(?:&(?:amp;)*quot;|[""'\]])", ROI);
        private static readonly Regex DxDbConn = new Regex(@"\b(?:Initial\s?Catalog|Database|dbname)\s*=\s*(?<d>[A-Za-z_][\w$#-]{0,127})(?=[;\s&""']|$)", ROI);
        private static readonly Regex DxDbWord = new Regex(@"\b(?:database|tenant database|replica set|pluggable database)\s(?:&(?:amp;)*quot;|[""'\[])(?<d>[A-Za-z_][\w$#.-]{0,127}?)(?:&(?:amp;)*quot;|[""'\]])", ROI);
        // SQL Server named instances ("HOST\INSTANCE")
        private static readonly Regex DxSqlInstance = new Regex(@"\b(?:Instance(?:Name)?|SqlInstance|ServerInstance|SqlServerInstance)\s*[=:]\s*(?:&(?:amp;)*quot;|[""'\[])?(?:(?<h>[A-Za-z0-9][\w.-]{0,62})\\{1,2})?(?<i>[A-Za-z_][\w$#-]{0,62})(?=&(?:amp;)*quot;|[""'\]\s,;]|$)", ROI);
        // Microsoft 365 tenant names and Entra ID / Azure identifiers
        private static readonly Regex DxM365Tenant = new Regex(@"(?<![\w.-])(?<t>[a-z0-9][a-z0-9-]{1,61}?)(?:-my|-admin|-files)?\.(?:sharepoint\.(?:com|us|de|cn)|(?:mail\.)?onmicrosoft\.(?:com|us|de))\b", ROI);
        private static readonly Regex DxCloudId = new Regex(@"(?:\b(?:tenant|application|app|directory|subscription|azure\s?ad\s?user|entra\s?user)[\s_]?id\b|\bclient_id\b|microsoftonline\.(?:com|us)/|/subscriptions/|/tenants/)(?:&(?:amp;)*quot;|[^A-Za-z0-9\r\n]){0,12}\{?(?<g>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", ROI);

        private static readonly HashSet<string> DefaultDbNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "master","model","msdb","tempdb","resource","mssqlsystemresource","tempdev","templog","modeldev","modellog",
            "msdbdata","msdblog","mastlog","distribution","ReportServer","ReportServerTempDB","SSISDB","DWConfiguration",
            "DWDiagnostics","DWQueue","VAO","postgres","template0","template1","admin","config","local","SYSTEMDB",
            "orcl","orclpdb","orclpdb1","orclcdb","xe","xepdb1","cdb$root","pdb$seed","SharePoint_Config","WSS_Content",
            "WSS_Logging","SharePoint_AdminContent","SearchService","SharePoint","sys","system","information_schema",
            "mysql","performance_schema","true","false","null","none","default","n/a","unknown","empty","primary","secondary",
            "data","log","rows","file","files","name","value","id"
        };
        private static readonly HashSet<string> DefaultSqlInstances = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "MSSQLSERVER","SQLEXPRESS","MICROSOFT##WID","MICROSOFT##SSEE","SHAREPOINT","SQL","SQLSERVER","LOCALDB","MSSQLLocalDB",
            "DEFAULT","NONE","NULL","TRUE","FALSE"
        };
        private static readonly Regex RxDefaultDbFile = new Regex(@"^(?:temp\d+|tempdev\d*|templog\d*|Veeam.*|VBR.*|VB365.*)$", ROI);

        // ================================================================== anonymization regexes
        private static readonly Regex AxIPv4 = new Regex(@"(?<!\d\.|\d)(?<ip>(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?!\d|\.\d)", RO);
        private static readonly Regex AxIPv6 = new Regex(@"(?:(?<=[G-Zg-z_]:)|(?<![\w:.]))(?<ip>[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?:%(?<z>[\w.]+))?(?![\w:]|\.\d)", RO);
        private static readonly Regex AxMac = new Regex(@"(?<![0-9A-Fa-f:-])(?<a>[0-9A-Fa-f]{2})(?<sep>[:-])(?<b>[0-9A-Fa-f]{2})\k<sep>(?<c>[0-9A-Fa-f]{2})\k<sep>(?<d>[0-9A-Fa-f]{2})\k<sep>(?<e>[0-9A-Fa-f]{2})\k<sep>(?<f>[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])", RO);
        private static readonly Regex AxSid = new Regex(@"\bS-1-5-21-(?<d>\d{1,10}-\d{1,10}-\d{1,10})(?=-\d|\b)", RO);
        private static readonly Regex AxBase64 = new Regex(@"(?<![A-Za-z0-9+/=])(?<b>[A-Za-z0-9+/]{8,8192}={0,2})(?![A-Za-z0-9+/=])", RO);

        private static readonly Regex CtxVersion = new Regex(@"(?:\b(?:version|ver|build|release|distrib(?:ution)?|assembly|module|patch|firmware|fw|revision|rev|productversion|fileversion|v))\W{0,12}$|\bversion\b[^\r\n]{0,30}$", ROI);
        private static readonly Regex CtxVersionWord = new Regex(@"\b(?:version|ver|build|distrib|assembly|productversion|fileversion|assemblyversion)\b\W{0,12}$", ROI);
        private static readonly Regex CtxUserAgent = new Regex(@"\b[A-Za-z][A-Za-z0-9_.-]{2,}/$", RO);
        private static readonly Regex CtxStrongPre = new Regex(@"(?:::ffff:|\bip(?:v4)?(?:\s?address(?:es)?)?|\baddress(?:es)?|\baddr|\bendpoint|\bgateway|\bdns(?:\s?servers?)?|\bsubnet|\bnetmask|\bpeer|\bremote(?:\s?ip)?|\bconnect(?:ing|ed)?\s+to|\bx-forwarded-for|\bhost|\bnat|\bip\s?range|\bwins|\bntp|\binterface|\broute|\bnext\s?hop)\W{0,6}$|::ffff:$|(?:^|[\s'""(\[=,;])\\{2,4}$|://$|@$", ROI);
        private static readonly Regex CtxStrongPost = new Regex(@"^(?::\d{1,5}\b|/\d{1,2}\b|%\d|\]:\d)", RO);

        // ================================================================== public helpers
        public void AddKeepTerm(string s) { if (!string.IsNullOrWhiteSpace(s)) KeepTerms.Add(s.Trim()); }
        public void AddWhitelistDomain(string s) { if (!string.IsNullOrWhiteSpace(s)) WhitelistDomains.Add(s.Trim().TrimStart('.')); }

        public void AddExtraTerm(string original, string fake)
        {
            if (string.IsNullOrWhiteSpace(original)) return;
            original = original.Trim();
            KeepTerms.Remove(original);
            AddCandidate(original, "Custom", "config", 1000000);
            if (!string.IsNullOrWhiteSpace(fake))
            {
                MapEntry e = new MapEntry { Category = "Custom", Original = original, Fake = fake.Trim(), Source = "config" };
                _terms[original] = e; _usedFakes.Add(e.Fake);
            }
        }

        private void Stat(string k, long n) { long v; _stats.TryGetValue(k, out v); _stats[k] = v + n; }

        private static readonly string[] CategoryOrder = { "Secret", "AccessKey", "Thumbprint", "CloudId", "Custom", "Tenant", "Domain", "Host", "SqlInstance", "Database", "User", "Job", "Repository", "Bucket", "StorageAccount", "Share", "Datastore", "VM", "Inventory" };
        private static int Prio(string c) { int i = Array.IndexOf(CategoryOrder, c); return i < 0 ? 99 : i; }

        private void AddCandidate(string value, string category, string source, long weight)
        {
            if (value == null) return;
            value = value.Trim().Trim('.', ',', ';', ':', '\'', '"', '[', ']', '(', ')', '{', '}');
            if (value.Length < 2) return;
            Candidate c;
            if (_cand.TryGetValue(value, out c))
            {
                c.Count += weight;
                if (Prio(category) < Prio(c.Category)) { c.Category = category; c.Source = source; }
            }
            else _cand[value] = new Candidate { Value = value, Category = category, Source = source, Count = weight };
        }

        private void AddCandidate(string value, string category, string source) { AddCandidate(value, category, source, 1); }

        // ---------------------------------------------------------------- validators
        private bool IsKeep(string s) { return KeepTerms.Contains(s); }

        private static bool HasLetter(string s) { foreach (char c in s) if (char.IsLetter(c)) return true; return false; }

        private bool IsHostLabel(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length > 63) return false;
            if (!RxLabel.IsMatch(s)) return false;
            if (!HasLetter(s)) return false;
            if (RxMoref.IsMatch(s) || RxHexish.IsMatch(s) || RxGuidPrefix.IsMatch(s) || RxHexPtr.IsMatch(s)) return false;
            if (Stop.Contains(s) || IsKeep(s)) return false;
            return true;
        }

        private static readonly Regex RxGuidPrefix = new Regex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-", RegexOptions.Compiled);
        private static readonly Regex RxHexPtr = new Regex(@"^0x[0-9a-fA-F]+$", RegexOptions.Compiled);
        private static readonly Regex RxDateish = new Regex(@"^\d{1,4}[./-]\d{1,2}[./-]\d{1,4}", RegexOptions.Compiled);
        private static bool HasDigitOrHyphen(string s) { foreach (char c in s) if (char.IsDigit(c) || c == '-') return true; return false; }
        private static bool IsCamel(string s) { return RxCamel.IsMatch(s); }
        private static bool IsUniformCase(string s) { return s == s.ToLowerInvariant() || s == s.ToUpperInvariant(); }

        // bare names found only through weak keyword contexts must look like a machine name
        private bool WeakHostOk(string h)
        {
            if (!IsHostLabel(h)) return false;
            if (HasDigitOrHyphen(h)) return !IsCamel(h.Replace("-", "")) || h.Any(char.IsDigit);
            return false;
        }

        private bool LooksLikeFqdn(string s)
        {
            if (s.Length > 253 || s.IndexOf('.') < 0) return false;
            string[] labels = s.Split('.');
            if (labels.Length < 2) return false;
            foreach (string l in labels) if (!RxLabel.IsMatch(l)) return false;
            string tld = labels[labels.Length - 1];
            if (!HasLetter(tld) || RxNumericish.IsMatch(tld)) return false;
            if (FileExt.Contains(tld) && !PublicTlds.Contains(tld)) return false;
            if (CodePrefixes.Contains(labels[0]) && labels.Length > 2) return false;
            return true;
        }

        private bool IsWhitelistedDomain(string fqdn)
        {
            string f = fqdn.ToLowerInvariant();
            foreach (string w in WhitelistDomains)
            {
                string wl = w.ToLowerInvariant();
                if (f == wl || f.EndsWith("." + wl)) return true;
            }
            return IsKeep(fqdn);
        }

        private bool IsUserName(string u)
        {
            if (string.IsNullOrEmpty(u) || u.Length < 2 || u.Length > 64) return false;
            if (u.IndexOf('%') >= 0 || u.IndexOf('&') >= 0 || u.IndexOf('~') >= 0) return false;
            if (RxGuidPrefix.IsMatch(u) || RxGuidAnywhere.IsMatch(u)) return false;
            if (!HasLetter(u)) return false;
            if (RxGuid.IsMatch(u) || RxHexish.IsMatch(u)) return false;
            string ul = u.ToLowerInvariant();
            if (Stop.Contains(u) || IsKeep(u)) return false;
            if (ul.StartsWith("mssql") || ul.StartsWith("sqltelemetry") || ul.StartsWith("veeam") || ul.StartsWith("nt ") || ul.StartsWith("umfd-") || ul.StartsWith("dwm-")) return false;
            return true;
        }

        private bool IsObjectName(string o)
        {
            if (string.IsNullOrWhiteSpace(o)) return false;
            o = o.Trim();
            if (o.Length < 2 || o.Length > 120) return false;
            if (!HasLetter(o)) return false;
            if (!char.IsLetterOrDigit(o[0])) return false;
            if (RxGuid.IsMatch(o) || RxMoref.IsMatch(o) || RxHexish.IsMatch(o) || RxHexPtr.IsMatch(o) || RxGuidPrefix.IsMatch(o)) return false;
            if (RxGuidAnywhere.IsMatch(o)) return false;                      // "CatalogConsolidation <guid>" = internal Veeam activity
            if (o.IndexOf('(') >= 0 || o.IndexOf(')') >= 0 || o.IndexOf('[') >= 0 || o.IndexOf(']') >= 0 || o.IndexOf('&') >= 0 || o.IndexOf('\'') >= 0 || o.IndexOf('"') >= 0) return false;
            int dot = o.IndexOf('.');
            if (dot > 0 && CodePrefixes.Contains(o.Substring(0, dot))) return false;   // System.Net..., Veeam.Backup...
            if (o.IndexOf(' ') < 0 && o.IndexOf('-') < 0 && o.IndexOf('_') < 0 && !o.Any(char.IsDigit) && IsCamel(o)) return false; // CamelCase identifiers
            if (Stop.Contains(o) || IsKeep(o)) return false;
            if (o.IndexOf(':') >= 0 || o.IndexOf('=') >= 0 || o.IndexOf('\\') >= 0 || o.IndexOf('/') >= 0 || o.IndexOf('<') >= 0 || o.IndexOf('{') >= 0) return false;
            if (o.Split(' ').Length > 6) return false;
            if (IsDefaultName(o)) return false;
            return true;
        }

        private static readonly Regex RxGuidAnywhere = new Regex(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", RegexOptions.Compiled);
        private static readonly Regex RxDefaultNames = new Regex(@"^(?:SecurityScopesRebuild|CatalogConsolidation|Catalog Cleanup|Audit Logs Archiving|BlobRepo|ConnectionCheck|Retention[ _]job.*|Checkpoint[ _]Removal|Database ?Resynchronizer|BestPracticesAnalyzer|Security & Compliance Analyzer|Logs? Export|Infrastructure update|Hyper-V CBT Data Rescan|Foreign transform|Transform job|Test Credentials|Rescan Change Tracking|Volumes Host Discover|ManageAccountOnObjectStorageRepository|Job\.\w+|GateRepoConnect|with grant type|TaskID|VeeamTmp_.*|Configuration Backup|Malware Detection.*|Sure ?Backup.*|Health Check|Compact|Synthetic.*|Active Full|Full|Incremental|Reverse Incremental|Backup Copy|Replica|Restore|Instant Recovery|File Level Restore|FLR|Quick Migration|Tape.*|Encryption Key.*|License.*|Session|Inventory|Backup[ _]Job[ _]\d+|Backup[ _]Copy[ _]Job[ _]\d+|Replication[ _]Job[ _]\d+|Default Backup Repository(?: \d+)?|Backup Repository \d+|Scale-out Backup Repository \d+|Backup Configuration Job|Backup_Configuration_Job|Protection Group \d+|Protection_Group_\d+|Manually Added|Manually_Added|Host Discovery|Host_Discovery|Malware Detection|Rescan of .*|Rescan_of_.*|Default|Discovered virtual machine|Virtual Machines|vm|Datacenters|host|Resources|Unknown|Capacity Tier|Performance Tier|Archive Tier|Configuration Database Resynchronize|Infrastructure Rescan|Export logs|Export_logs|Checkpoint Removal|Retention|Update Settings Synchronization|Scan Specific Backup|Resource Scan)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static bool IsDefaultName(string s) { return RxDefaultNames.IsMatch(s.Trim()); }

        // ================================================================== discovery
        private static readonly HashSet<string> SystemBackupFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "Audit","CloudConnectService","CoordinatorService","Endpoint","ExplorerStandByService","Export_logs","FLRSessions",
            "Host_Discovery","Malware_Detection_Logs","PerformanceRestAPI","Plugin","Plugins","RegistryOptions","Rescan",
            "ResourceScan","Satellites","Scan_Specific_Backup","System","Update_Settings_Synchronization","Utils","Yarp",
            "Backup_Configuration_Job","Logs","Backup","Other","Managed","AgentLogs","Console","PowerShell","Windows","Linux",
            "Configuration_Database_Resynchronize","Infrastructure_Rescan","Retention","CheckpointRemoval","Tape","CDP"
        };

        private static readonly Regex RxTaskSuffix = new Regex(@"(?:\.vm-\d+(?:\.\d+)?|\.[0-9a-fA-F]{8}-[0-9a-fA-F-]{27})$", RegexOptions.Compiled);
        private static readonly Regex RxTruncated = new Regex(@"^.{25,}_[A-Za-z0-9]{4}$", RegexOptions.Compiled);   // Veeam truncates long names and appends _XXXX
        private static readonly Regex PxTask = new Regex(@"^Task\.(?<o>.+?)\.log(?:\.\d+)?$", ROI);
        private static readonly Regex PxAgentTask = new Regex(@"^Agent\.Task\.(?<o>.+?)\.vm-\d+\.", ROI);
        private static readonly Regex PxJob = new Regex(@"^Job\.(?<j>.+?)(?:\.Backup|\.Replica|\.Copy)?\.log$", ROI);

        public void DiscoverPath(string relPath)
        {
            if (string.IsNullOrEmpty(relPath)) return;
            string[] seg = relPath.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (seg.Length == 0) return;
            // top-level folder of a Veeam bundle = computer name (sometimes FQDN)
            string top = seg[0];
            if (seg.Length > 1 && !top.EndsWith("~unz"))
            {
                if (top.IndexOf('.') > 0 && LooksLikeFqdn(top)) { _strongFqdn.Add(top); CountFqdn(top, 1000); }
                else if (IsHostLabel(top)) AddCandidate(top, "Host", "bundle-root", 1000);
            }
            string file = seg[seg.Length - 1];
            string parent = seg.Length > 1 ? seg[seg.Length - 2] : "";
            Match m = PxTask.Match(file);
            if (m.Success)
            {
                string o = RxTaskSuffix.Replace(m.Groups["o"].Value, "");
                if (!RxTruncated.IsMatch(o) && !o.StartsWith("Transform.", StringComparison.OrdinalIgnoreCase) && !o.StartsWith("WMS.", StringComparison.OrdinalIgnoreCase) && IsObjectName(o))
                    AddCandidate(o, "VM", "file:Task", 50);
            }
            m = PxAgentTask.Match(file);
            if (m.Success && IsObjectName(m.Groups["o"].Value)) AddCandidate(m.Groups["o"].Value, "VM", "file:Agent.Task", 50);
            m = PxJob.Match(file);
            if (m.Success)
            {
                string j = m.Groups["j"].Value;
                {
                    if (j.StartsWith("Rescan_of_", StringComparison.OrdinalIgnoreCase))
                    {
                        string pg = j.Substring(10);
                        if (IsObjectName(pg)) AddCandidate(pg, "Job", "file:Rescan", 50);
                    }
                    else if (IsObjectName(j) && !SystemBackupFolders.Contains(j)) AddCandidate(j, "Job", "file:Job", 50);
                }
            }
            // job folders directly under <root>\Backup\<J>\ with Agent.<J>.* / Job.<J>.* files
            for (int i = 1; i < seg.Length - 1; i++)
            {
                if (!string.Equals(seg[i - 1], "Backup", StringComparison.OrdinalIgnoreCase)) continue;
                string j = seg[i];
                if (SystemBackupFolders.Contains(j)) continue;
                if (file.StartsWith("Agent." + j + ".", StringComparison.OrdinalIgnoreCase) || file.StartsWith("Job." + j + ".", StringComparison.OrdinalIgnoreCase))
                    if (IsObjectName(j)) AddCandidate(j, "Job", "folder:Job", 50);
            }
        }

        private void CountFqdn(string f, long w)
        {
            long v; _fqdnTokens.TryGetValue(f, out v); _fqdnTokens[f] = v + w;
        }

        private void HostCandidate(string h, string source, bool strong)
        {
            if (string.IsNullOrEmpty(h)) return;
            h = h.Trim().TrimEnd('.').TrimEnd('$');
            if (h.Length < 2) return;
            IPAddress tmp;
            if (IPAddress.TryParse(h, out tmp)) return;
            if (h.IndexOf('.') > 0)
            {
                if (!LooksLikeFqdn(h)) return;
                if (strong) _strongFqdn.Add(h);
                CountFqdn(h, strong ? 10 : 1);
            }
            else if (StrongBareSources.Contains(source) ? IsHostLabel(h) : WeakHostOk(h)) AddCandidate(h, "Host", source);
        }

        private static readonly HashSet<string> StrongBareSources = new HashSet<string>(StringComparer.Ordinal) {
            "url", "unc", "host:port", "computer-account", "bundle-root", "user@"
        };

        public void DiscoverText(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            Match m;
            for (m = DxUrl.Match(text); m.Success; m = m.NextMatch())
            {
                HostCandidate(m.Groups["h"].Value, "url", true);
                if (m.Groups["u"].Success && IsUserName(m.Groups["u"].Value)) AddCandidate(m.Groups["u"].Value, "User", "url");
                if (m.Groups["p"].Success && IsSecretValue(m.Groups["p"].Value)) AddCandidate(m.Groups["p"].Value, "Secret", "url");
            }
            for (m = DxUnc.Match(text); m.Success; m = m.NextMatch())
            {
                HostCandidate(m.Groups["h"].Value, "unc", true);
                string s = m.Groups["s"].Value.Trim();
                if (!StopShares.Contains(s) && IsObjectName(s) && s.Length >= 3) AddCandidate(s, "Share", "unc");
            }
            for (m = DxHostKw.Match(text); m.Success; m = m.NextMatch()) HostCandidate(m.Groups["h"].Value, "kw:host", true);
            for (m = DxHostKwFqdn.Match(text); m.Success; m = m.NextMatch()) HostCandidate(m.Groups["h"].Value, "kw:host", true);
            for (m = DxHostPort.Match(text); m.Success; m = m.NextMatch()) HostCandidate(m.Groups["h"].Value, "host:port", true);
            for (m = DxCn.Match(text); m.Success; m = m.NextMatch()) HostCandidate(m.Groups["h"].Value, "cn", true);
            for (m = DxIqn.Match(text); m.Success; m = m.NextMatch()) HostCandidate(m.Groups["h"].Value, "iqn", true);
            for (m = DxSmtp.Match(text); m.Success; m = m.NextMatch()) HostCandidate(m.Groups["h"].Value, "smtp", true);
            for (m = DxDomUser.Match(text); m.Success; m = m.NextMatch())
            {
                string d = m.Groups["d"].Value, u = m.Groups["u"].Value.TrimEnd('.');
                if (!IsKeep(d) && !Stop.Contains(d))
                {
                    if (d.IndexOf('.') > 0) { if (LooksLikeFqdn(d) && !IsWhitelistedDomain(d)) { _strongFqdn.Add(d); _suffixes.Add(d); CountFqdn(d, 5); } }
                    else if (IsHostLabel(d)) AddCandidate(d, "Domain", "domain\\user");
                }
                if (u.EndsWith("$")) HostCandidate(u, "computer-account", true);
                else if (IsUserName(u)) AddCandidate(u, "User", "domain\\user");
            }
            for (m = DxUser.Match(text); m.Success; m = m.NextMatch())
            {
                string u = m.Groups["u"].Value.TrimEnd('.');
                if (u.EndsWith("$")) { HostCandidate(u, "computer-account", true); continue; }
                // weak context: accept only names that look like accounts (jdoe, j.smith, svc_backup, ADMIN01), not identifiers (LoginRequest, String)
                bool accountLike = !IsCamel(u) && (IsUniformCase(u) && u == u.ToLowerInvariant() || u.Any(c => char.IsDigit(c) || c == '.' || c == '_' || c == '-'));
                if (accountLike && IsUserName(u)) AddCandidate(u, "User", "kw:user");
                if (m.Groups["f"].Success) HostCandidate(m.Groups["f"].Value, "user@", true);
            }
            for (m = DxHome.Match(text); m.Success; m = m.NextMatch()) { string u = m.Groups["u"].Value; if (IsUserName(u)) AddCandidate(u, "User", "home"); }
            for (m = DxWinProfile.Match(text); m.Success; m = m.NextMatch())
            {
                string u = m.Groups["u"].Value.Trim();
                int dot = u.IndexOf('.');
                if (dot > 0) { string dom = u.Substring(dot + 1); u = u.Substring(0, dot); if (IsHostLabel(dom)) AddCandidate(dom, "Domain", "profile"); }
                if (IsUserName(u)) AddCandidate(u, "User", "profile");
            }
            for (m = DxEmail.Match(text); m.Success; m = m.NextMatch())
            {
                string u = m.Groups["u"].Value, f = m.Groups["f"].Value;
                if (!LooksLikeFqdn(f)) continue;
                if (IsWhitelistedDomain(f)) continue;
                HostCandidate(f, "email", true);
                int dot = u.LastIndexOf('.');
                bool fileLike = dot > 0 && FileExt.Contains(u.Substring(dot + 1));
                if (!fileLike) _suffixes.Add(f);       // "disk.vmdk@esx01.lan" -> esx01 is a host, not a mail domain
                if (!fileLike && IsUserName(u)) AddCandidate(u, "User", "email");
            }
            for (m = DxJob.Match(text); m.Success; m = m.NextMatch()) { string j = m.Groups["j"].Value.Trim(); if (IsObjectName(j)) AddCandidate(j, "Job", "kw:job"); }
            for (m = DxJobName.Match(text); m.Success; m = m.NextMatch()) { string j = m.Groups["j"].Value.Trim(); if (IsObjectName(j)) AddCandidate(j, "Job", "kw:jobname"); }
            for (m = DxRepoName.Match(text); m.Success; m = m.NextMatch()) { string r = m.Groups["r"].Value.Trim(); if (IsObjectName(r)) AddCandidate(r, "Repository", "kw:reponame"); }
            for (m = DxRepoQ.Match(text); m.Success; m = m.NextMatch()) { string r = m.Groups["r"].Value.Trim(); if (IsObjectName(r)) AddCandidate(r, "Repository", "kw:repo"); }
            for (m = DxRepoGuid.Match(text); m.Success; m = m.NextMatch()) { string r = m.Groups["r"].Value.Trim(); if (IsObjectName(r)) AddCandidate(r, "Repository", "kw:repo(guid)"); }
            for (m = DxBucket.Match(text); m.Success; m = m.NextMatch()) { string b = m.Groups["b"].Value; if (IsObjectName(b) && b.Length >= 3) AddCandidate(b, "Bucket", "kw:bucket"); }
            for (m = DxS3Vhost.Match(text); m.Success; m = m.NextMatch()) { string b = m.Groups["b"].Value; if (!b.StartsWith("s3", StringComparison.OrdinalIgnoreCase) && IsObjectName(b)) AddCandidate(b, "Bucket", "s3-vhost"); }
            for (m = DxAzureAcct.Match(text); m.Success; m = m.NextMatch()) AddCandidate(m.Groups["a"].Value, "StorageAccount", "azure-host");
            for (m = DxAzureAcct2.Match(text); m.Success; m = m.NextMatch()) { string a = m.Groups["a"].Value; if (!Stop.Contains(a)) AddCandidate(a, "StorageAccount", "azure-kw"); }
            for (m = DxAccessKey.Match(text); m.Success; m = m.NextMatch())
            {
                string k = m.Groups["k"].Value;
                if (HasLetter(k) && k.Any(char.IsDigit) && !RxHexish.IsMatch(k)) AddCandidate(k, "AccessKey", "kw:accesskey");
            }
            for (m = DxAwsKey.Match(text); m.Success; m = m.NextMatch()) AddCandidate(m.Groups["k"].Value, "AccessKey", "aws-pattern");
            for (m = DxSecret.Match(text); m.Success; m = m.NextMatch())
            {
                string s = m.Groups["s"].Value;
                if (IsSecretValue(s)) AddCandidate(s, "Secret", "kw:secret");
            }
            for (m = DxBearer.Match(text); m.Success; m = m.NextMatch()) { string s = m.Groups["s"].Value; if (IsSecretValue(s)) AddCandidate(s, "Secret", "bearer"); }
            for (m = DxJwt.Match(text); m.Success; m = m.NextMatch()) AddCandidate(m.Groups["s"].Value, "Secret", "jwt");
            for (m = DxObject.Match(text); m.Success; m = m.NextMatch()) { string o = m.Groups["o"].Value.Trim(); if (IsObjectName(o)) AddCandidate(o, "VM", "kw:vm"); }
            for (m = DxVmx.Match(text); m.Success; m = m.NextMatch())
            {
                string ds = m.Groups["ds"].Value.Trim(), o = m.Groups["o"].Value.Trim();
                if (!m.Groups["f"].Value.StartsWith(o, StringComparison.OrdinalIgnoreCase)) continue;
                if (IsObjectName(ds)) AddCandidate(ds, "Datastore", "vmx-path");
                if (IsObjectName(o)) AddCandidate(o, "VM", "vmx-path");
            }
            for (m = DxDatacenter.Match(text); m.Success; m = m.NextMatch()) { string i = m.Groups["i"].Value.Trim(); if (IsObjectName(i)) AddCandidate(i, "Inventory", "datacenter"); }
            for (m = DxNameRef.Match(text); m.Success; m = m.NextMatch())
            {
                string nm = m.Groups["n"].Value.Trim(), t = m.Groups["t"].Value.ToLowerInvariant();
                if (!IsObjectName(nm)) continue;
                if (t == "datastore" || t == "storagepod") AddCandidate(nm, "Datastore", "vsphere-ref");
                else if (t == "vm") AddCandidate(nm, "VM", "vsphere-ref");
                else if (t == "host") HostCandidate(nm, "host:port", true);
                else AddCandidate(nm, "Inventory", "vsphere-ref:" + t);
            }
            for (m = DxVmColon.Match(text); m.Success; m = m.NextMatch()) { string o = m.Groups["o"].Value; if (IsObjectName(o)) AddCandidate(o, "VM", "kw:vm"); }
            // KB2462 categories
            for (m = DxThumb.Match(text); m.Success; m = m.NextMatch()) { string v = m.Groups["v"].Value; if (IsFingerprintValue(v)) AddCandidate(v, "Thumbprint", "kw:thumbprint"); }
            for (m = DxSshKeyFp.Match(text); m.Success; m = m.NextMatch()) { string v = m.Groups["v"].Value; if (IsFingerprintValue(v)) AddCandidate(v, "Thumbprint", "ssh-fingerprint"); }
            for (m = DxDbQ.Match(text); m.Success; m = m.NextMatch()) DbCandidate(m.Groups["d"].Value, "kw:database");
            for (m = DxDbConn.Match(text); m.Success; m = m.NextMatch()) DbCandidate(m.Groups["d"].Value, "connection-string");
            for (m = DxDbWord.Match(text); m.Success; m = m.NextMatch()) DbCandidate(m.Groups["d"].Value, "kw:database");
            for (m = DxSqlInstance.Match(text); m.Success; m = m.NextMatch())
            {
                string i = m.Groups["i"].Value;
                if (DefaultSqlInstances.Contains(i) || i.StartsWith("VEEAMSQL", StringComparison.OrdinalIgnoreCase) || IsKeep(i) || Stop.Contains(i)) continue;
                if (!m.Groups["h"].Success && !HasDigitOrHyphen(i) && i != i.ToUpperInvariant()) continue;   // bare word: accept only INSTANCE-like names
                if (IsObjectName(i) && i.Length >= 3) AddCandidate(i, "SqlInstance", "kw:instance");
            }
            for (m = DxM365Tenant.Match(text); m.Success; m = m.NextMatch()) { string t = m.Groups["t"].Value; if (t.Length >= 3 && IsObjectName(t) && !IsKeep(t)) AddCandidate(t, "Tenant", "m365-domain"); }
            for (m = DxCloudId.Match(text); m.Success; m = m.NextMatch())
            {
                string g = m.Groups["g"].Value;
                if (g.Trim('0', '-').Length == 0) continue;     // empty GUID
                AddCandidate(g, "CloudId", "kw:cloud-id");
            }
            if (_domUsers.Count < 20000)
                for (m = DxAnyDomUser.Match(text); m.Success; m = m.NextMatch())
                {
                    string d = m.Groups["d"].Value, u = m.Groups["u"].Value.TrimEnd('.');
                    HashSet<string> set;
                    if (!_domUsers.TryGetValue(d, out set)) { set = new HashSet<string>(StringComparer.OrdinalIgnoreCase); _domUsers[d] = set; }
                    if (set.Count < 200) set.Add(u);
                }
            for (m = DxInvPath.Match(text); m.Success; m = m.NextMatch()) _inventoryPaths.Add(m.Groups["p"].Value);
            for (m = DxInvPath2.Match(text); m.Success; m = m.NextMatch()) _inventoryPaths.Add(m.Groups["p"].Value);
            for (m = DxFqdnToken.Match(text); m.Success; m = m.NextMatch())
            {
                string f = m.Groups["f"].Value;
                int dot = f.LastIndexOf('.');
                string tld = f.Substring(dot + 1);
                if (!HasLetter(tld) || FileExt.Contains(tld) && !PublicTlds.Contains(tld)) continue;
                CountFqdn(f, 1);
            }
            // IPv4 contexts (versions vs. real addresses)
            for (m = AxIPv4.Match(text); m.Success; m = m.NextMatch())
            {
                string ip = m.Groups["ip"].Value;
                IpStat st;
                if (!_ip.TryGetValue(ip, out st)) { st = new IpStat(); _ip[ip] = st; }
                st.Total++;
                string pre = Pre(text, m.Index, 40);
                string post = Post(text, m.Index + m.Length, 8);
                if (CtxStrongPre.IsMatch(pre) || CtxStrongPost.IsMatch(post)) st.Strong++;
                if (CtxVersionWord.IsMatch(pre)) { st.Version++; st.VersionWord++; }
                else if (CtxVersion.IsMatch(pre) || CtxUserAgent.IsMatch(pre)) st.Version++;
            }
        }

        private static string Pre(string t, int idx, int len) { int s = Math.Max(0, idx - len); return t.Substring(s, idx - s); }
        private static string Post(string t, int idx, int len) { int l = Math.Min(len, t.Length - idx); return l <= 0 ? "" : t.Substring(idx, l); }

        private static bool IsSecretValue(string s)
        {
            if (s == null) return false;
            s = s.Trim().Trim('[', ']', '(', ')', '{', '}', '\'', '"', '<', '>', ',', ';', '.');
            if (s.Length < 4) return false;
            string l = s.ToLowerInvariant();
            if (l == "yes" || l == "no" || l == "on" || l == "off" || l == "enabled" || l == "disabled" || l == "required" || l == "optional" || l == "changed" || l == "expired" || l == "valid" || l == "invalid" || l == "specified" || l == "provided" || l == "saved" || l == "updated") return false;
            if (IsMasked(s)) return false;
            if (RxGuidPrefix.IsMatch(s) || RxGuidAnywhere.IsMatch(s) || RxDateish.IsMatch(s) || RxNumericish.IsMatch(s)) return false;
            return true;
        }

        private static bool IsFingerprintValue(string v)
        {
            if (string.IsNullOrEmpty(v) || RxGuidAnywhere.IsMatch(v)) return false;
            string hex = v.Replace(":", "").Replace("-", "");
            bool isHex = hex.All(Uri.IsHexDigit);
            if (isHex)
            {
                if (hex.Distinct().Count() < 4) return false;            // 0000..., FFFF...
                return hex.Any(char.IsDigit) && hex.Any(char.IsLetter);
            }
            // base64 SSH fingerprint: mixed case + digits, not a word
            return v.Any(char.IsDigit) && v.Any(char.IsUpper) && v.Any(char.IsLower);
        }

        private void DbCandidate(string d, string source)
        {
            if (string.IsNullOrEmpty(d)) return;
            d = d.Trim().TrimEnd('.');
            // SQL logical file names: "<db>_log", "<db>_data"
            string baseName = Regex.Replace(d, @"(?i)_(?:log|data|dat|primary)(?:_?\d+)?$", "");
            if (baseName.Length >= 3) d = baseName;
            if (d.Length < 3 || DefaultDbNames.Contains(d) || RxDefaultDbFile.IsMatch(d)) return;
            if (IsKeep(d) || Stop.Contains(d)) return;
            if (!IsObjectName(d) && !(IsCamel(d) && IsObjectName(d + "_x"))) return;   // CamelCase is normal for database names
            AddCandidate(d, "Database", source);
        }

        private int _fpCounter;
        // format-preserving placeholder for a thumbprint / fingerprint (same length, separators and alphabet)
        private string MakeFingerprintFake(string original)
        {
            _fpCounter++;
            string hex = original.Replace(":", "").Replace("-", "");
            string fake;
            if (hex.All(Uri.IsHexDigit))
            {
                string n = _fpCounter.ToString("x");
                string body = ("aa" + new string('0', Math.Max(0, hex.Length - 2 - n.Length)) + n);
                if (body.Length > hex.Length) body = body.Substring(body.Length - hex.Length);
                if (original.Any(char.IsLetter) && original.Where(char.IsLetter).All(char.IsUpper)) body = body.ToUpperInvariant();
                char sep = original.IndexOf(':') >= 0 ? ':' : original.IndexOf('-') >= 0 ? '-' : '\0';
                if (sep == '\0') fake = body;
                else
                {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < body.Length; i += 2) { if (i > 0) sb.Append(sep); sb.Append(body, i, Math.Min(2, body.Length - i)); }
                    fake = sb.ToString();
                }
            }
            else
            {
                bool pad = original.EndsWith("=");
                int len = original.Length - (pad ? 1 : 0);
                string n = _fpCounter.ToString();
                fake = "ANONFINGERPRINT";
                fake = fake + new string('0', Math.Max(0, len - fake.Length - n.Length)) + n;
                if (pad) fake += "=";
            }
            if (_usedFakes.Contains(fake)) return MakeFingerprintFake(original);
            _usedFakes.Add(fake);
            return fake;
        }

        private int _guidCounter;
        private string MakeGuidFake()
        {
            _guidCounter++;
            string f = "a0a0a0a0-0000-4000-8000-" + _guidCounter.ToString().PadLeft(12, '0');
            _usedFakes.Add(f);
            return f;
        }

        private static bool IsMasked(string s)
        {
            if (string.IsNullOrEmpty(s)) return true;
            string t = s.Trim('*', ' ', '"', '\'', '[', ']', '<', '>', '(', ')');
            if (t.Length == 0) return true;
            string l = t.ToLowerInvariant();
            return l == "hidden" || l == "null" || l == "none" || l == "true" || l == "false" || l == "empty" || l == "masked"
                || l == "redacted" || l == "password" || l == "secret" || l.StartsWith("{") || l.StartsWith("$") || l == "xxxx" || l == "..."
                || l == "not" || l == "is" || l == "was" || l == "for" || l == "has" || l == "will" || l == "set" || l == "from"
                || l.All(c => c == 'x' || c == '*' || c == '#' || c == '.');
        }

        // ================================================================== finalize
        private string NextFake(string category)
        {
            string prefix; int width;
            switch (category)
            {
                case "Host": prefix = "host"; width = 3; break;
                case "Domain": prefix = "domain"; width = 2; break;
                case "User": prefix = "user"; width = 3; break;
                case "Job": prefix = "job"; width = 3; break;
                case "Repository": prefix = "repo"; width = 2; break;
                case "Bucket": prefix = "bucket"; width = 2; break;
                case "StorageAccount": prefix = "storageacct"; width = 2; break;
                case "Share": prefix = "share"; width = 2; break;
                case "Datastore": prefix = "datastore"; width = 2; break;
                case "VM": prefix = "vm"; width = 3; break;
                case "Inventory": prefix = "inventory"; width = 2; break;
                case "Secret": prefix = "REDACTED-SECRET-"; width = 3; break;
                case "AccessKey": prefix = "ANONACCESSKEY"; width = 7; break;
                case "Database": prefix = "db"; width = 3; break;
                case "SqlInstance": prefix = "SQLINST"; width = 2; break;
                case "Tenant": prefix = "tenant"; width = 2; break;
                default: prefix = "term"; width = 3; break;
            }
            while (true)
            {
                int n; _counters.TryGetValue(category, out n); n++; _counters[category] = n;
                string f = prefix + n.ToString().PadLeft(width, '0');
                if (_usedFakes.Contains(f) || _cand.ContainsKey(f) || _terms.ContainsKey(f)) continue;
                _usedFakes.Add(f);
                return f;
            }
        }

        private MapEntry GetOrCreate(string original, string category, string source, bool bare)
        {
            MapEntry e;
            if (_terms.TryGetValue(original, out e))
            {
                if (bare) e.Bare = true;
                return e;
            }
            string fake = category == "Thumbprint" ? MakeFingerprintFake(original)
                        : category == "CloudId" ? MakeGuidFake()
                        : NextFake(category);
            e = new MapEntry { Category = category, Original = original, Fake = fake, Bare = bare, Source = source };
            _terms[original] = e;
            return e;
        }

        private bool IsInternalSuffix(string suffix)
        {
            if (_suffixes.Contains(suffix)) return true;
            string tld = suffix.Substring(suffix.LastIndexOf('.') + 1);
            return InternalTlds.Contains(tld);
        }

        private bool AcceptFqdn(string f, out bool isInternal)
        {
            isInternal = false;
            if (!LooksLikeFqdn(f) || IsWhitelistedDomain(f)) return false;
            string[] labels = f.Split('.');
            string tld = labels[labels.Length - 1];
            string suffix = f.Substring(f.IndexOf('.') + 1);
            // learned suffix (e.g. "corp", "contoso.lan")
            foreach (string s in _suffixes)
                if (string.Equals(f, s, StringComparison.OrdinalIgnoreCase) || f.EndsWith("." + s, StringComparison.OrdinalIgnoreCase)) { isInternal = true; return true; }
            bool uniformCase = f == f.ToLowerInvariant() || f == f.ToUpperInvariant();
            if (InternalTlds.Contains(tld))
            {
                if (CodePrefixes.Contains(labels[0])) return false;
                if (!uniformCase && !_strongFqdn.Contains(f)) return false;   // PascalCase => .NET namespace
                isInternal = true; return true;
            }
            if (_strongFqdn.Contains(f))
            {
                if (PublicTlds.Contains(tld) || InternalTlds.Contains(tld)) { isInternal = !PublicTlds.Contains(tld); return true; }
                // unknown TLD that was not learned as a suffix (e.g. truncated "host.stat")
                return false;
            }
            if (PublicTlds.Contains(tld))
            {
                if (CodePrefixes.Contains(labels[0])) return false;
                bool lower = f == f.ToLowerInvariant();
                bool upper = f == f.ToUpperInvariant();
                if (!lower && !upper) return false;
                // "x.com" / "x.cloud" without network context is too often a file name or a config key
                if (labels.Length == 2) return false;
                if (RxNumericish.IsMatch(labels[0])) return false;
                return true;
            }
            return false;
        }

        private static string NormName(string s) { return s.ToLowerInvariant().Replace('_', ' ').Trim(); }

        public void FinalizeDiscovery()
        {
            // 1) learn domain suffixes from strong FQDN contexts
            foreach (string f in _strongFqdn)
            {
                if (IsWhitelistedDomain(f)) continue;
                int dot = f.IndexOf('.');
                if (dot <= 0) continue;
                string suffix = f.Substring(dot + 1);
                string tld = suffix.Substring(suffix.LastIndexOf('.') + 1);
                if (PublicTlds.Contains(tld) && suffix.IndexOf('.') < 0) continue; // "acme.com": don't learn "com"
                if (RxNumericish.IsMatch(suffix) || FileExt.Contains(tld)) continue;
                if (CodePrefixes.Contains(f.Split('.')[0])) continue;
                _suffixes.Add(suffix);
            }
            // drop truncated suffixes ("cor" when "corp" exists) and too short ones
            List<string> sufList = _suffixes.ToList();
            foreach (string s in sufList)
            {
                bool drop = false;
                if (s.IndexOf('.') < 0)
                {
                    if (s.Length < 3 && !InternalTlds.Contains(s)) drop = true;
                    foreach (string t in sufList)
                        if (t.Length > s.Length && t.IndexOf('.') < 0 && t.StartsWith(s, StringComparison.OrdinalIgnoreCase)) { drop = true; break; }
                }
                else
                {
                    string last = s.Substring(s.LastIndexOf('.') + 1);
                    foreach (string t in sufList)
                    {
                        if (t.IndexOf('.') < 0 || t.Length <= s.Length) continue;
                        string tl = t.Substring(t.LastIndexOf('.') + 1);
                        if (t.StartsWith(s.Substring(0, s.LastIndexOf('.') + 1), StringComparison.OrdinalIgnoreCase) && tl.StartsWith(last, StringComparison.OrdinalIgnoreCase) && tl.Length > last.Length) { drop = true; break; }
                    }
                }
                if (drop) _suffixes.Remove(s);
            }

            // 2) accept FQDN tokens
            List<string> fqdns = new List<string>();
            foreach (KeyValuePair<string, long> kv in _fqdnTokens)
            {
                bool internalF;
                if (AcceptFqdn(kv.Key, out internalF)) fqdns.Add(kv.Key);
            }
            fqdns = fqdns.Select(x => x.ToLowerInvariant()).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();

            // 3) domain labels from suffixes first (so "contoso" -> domainNN everywhere)
            foreach (string s in _suffixes.Select(x => x.ToLowerInvariant()).Distinct().OrderBy(x => x, StringComparer.Ordinal))
            {
                if (IsWhitelistedDomain(s)) continue;
                string[] labels = s.Split('.');
                for (int i = 0; i < labels.Length; i++)
                {
                    bool isTld = (i == labels.Length - 1) && labels.Length > 1;
                    if (isTld && (KeepTldInFake.Contains(labels[i]) || PublicTlds.Contains(labels[i]))) continue;
                    if (labels.Length == 1 && KeepTldInFake.Contains(labels[i])) continue;
                    if (_terms.ContainsKey(labels[i])) continue;
                    bool bare = labels[i].Length >= Math.Max(3, MinBareTermLength) && !Stop.Contains(labels[i]) && !IsKeep(labels[i]) && HasLetter(labels[i]);
                    // single-label custom domains such as "corp" are worth replacing even if generic
                    if (labels.Length == 1 && HasLetter(labels[i]) && labels[i].Length >= 3 && !IsKeep(labels[i])) bare = true;
                    GetOrCreate(labels[i], "Domain", "suffix", bare);
                }
            }

            // 4) host labels of the FQDNs (so that "srv-app01" is a Host even if also seen as "SRV-APP01\user")
            foreach (string f in fqdns)
            {
                if (_suffixes.Contains(f)) continue;
                bool internalF; AcceptFqdn(f, out internalF);
                string l = f.Split('.')[0];
                if (_terms.ContainsKey(l)) continue;
                bool bare = internalF && IsHostLabel(l) && l.Length >= MinBareTermLength;
                // a weak bare candidate with the same name confirms it
                Candidate c;
                if (!bare && _cand.TryGetValue(l, out c) && IsHostLabel(l) && l.Length >= MinBareTermLength) bare = true;
                GetOrCreate(l, "Host", "fqdn", bare);
            }

            // 5) other candidates in priority order (stable categories / numbering)
            List<Candidate> cands = _cand.Values
                .Where(c => !IsKeep(c.Value) && !Stop.Contains(c.Value))
                .OrderBy(c => Prio(c.Category)).ThenBy(c => c.Value.ToLowerInvariant(), StringComparer.Ordinal).ToList();
            Dictionary<string, MapEntry> norm = new Dictionary<string, MapEntry>(StringComparer.Ordinal);
            foreach (MapEntry e in _terms.Values) { string k = NormName(e.Original); if (!norm.ContainsKey(k)) norm[k] = e; }
            HashSet<string> jobNorms = new HashSet<string>(cands.Where(c => c.Category == "Job").Select(c => NormName(c.Value)), StringComparer.Ordinal);
            foreach (Candidate c in cands)
            {
                if (c.Category == "Host" || c.Category == "Domain")
                {
                    if (!IsHostLabel(c.Value) && !(c.Category == "Domain" && HasLetter(c.Value))) continue;
                    if (c.Value.Length < MinBareTermLength) continue;
                }
                MapEntry existing;
                if (_terms.TryGetValue(c.Value, out existing)) { existing.Bare = true; continue; }
                string nk = NormName(c.Value);
                if (c.Category != "Secret" && c.Category != "AccessKey" && c.Category != "Thumbprint" && c.Category != "CloudId" && norm.TryGetValue(nk, out existing))
                {
                    // "web01_Backup" and "web01 Backup" are the same job: reuse the placeholder
                    MapEntry alias = new MapEntry { Category = existing.Category, Original = c.Value, Fake = existing.Fake, Bare = true, Source = c.Source + " (alias)" };
                    _terms[c.Value] = alias;
                    continue;
                }
                // "<job> - <object>" task names: the two halves are anonymized separately
                int sep = nk.IndexOf(" - ", StringComparison.Ordinal);
                if (c.Category == "Job" && sep > 0)
                {
                    // register the job half on its own (unless it is a Veeam default name)
                    string left = c.Value.Substring(0, sep).Trim();
                    if (IsObjectName(left) && !Stop.Contains(left) && !IsKeep(left) && !_terms.ContainsKey(left) && !norm.ContainsKey(NormName(left)))
                    {
                        MapEntry je = GetOrCreate(left, "Job", c.Source + " (split)", true);
                        norm[NormName(left)] = je;
                    }
                    continue;
                }
                MapEntry ne = GetOrCreate(c.Value, c.Category, c.Source, true);
                ne.Bare = true;
                if (!norm.ContainsKey(nk)) norm[nk] = ne;
            }

            // 6) FQDNs: label-wise mapping ("srv-app01.corp" -> "host001.domain02")
            foreach (string f in fqdns)
            {
                bool internalF; AcceptFqdn(f, out internalF);
                string[] labels = f.Split('.');
                bool isDomainOnly = _suffixes.Contains(f);
                StringBuilder fake = new StringBuilder();
                for (int i = 0; i < labels.Length; i++)
                {
                    string l = labels[i];
                    bool isTld = i == labels.Length - 1;
                    string part;
                    if (isTld && (KeepTldInFake.Contains(l) || PublicTlds.Contains(l))) part = l;
                    else
                    {
                        MapEntry le;
                        if (_terms.TryGetValue(l, out le)) part = le.Fake;
                        else
                        {
                            string cat = (i == 0 && !isDomainOnly) ? "Host" : "Domain";
                            le = GetOrCreate(l, cat, "fqdn", false);
                            part = le.Fake;
                        }
                    }
                    if (i > 0) fake.Append('.');
                    fake.Append(part);
                }
                MapEntry fe;
                if (!_terms.TryGetValue(f, out fe))
                {
                    fe = new MapEntry { Category = "FQDN", Original = f, Fake = fake.ToString(), Bare = true, Source = internalF ? "fqdn-internal" : "fqdn-public" };
                    _terms[f] = fe;
                }
            }

            // 6b) "<known host or domain>\<account>" anywhere in the logs
            foreach (KeyValuePair<string, HashSet<string>> kv in _domUsers)
            {
                MapEntry de;
                if (!_terms.TryGetValue(kv.Key, out de)) continue;
                if (de.Category != "Host" && de.Category != "FQDN" && de.Category != "Domain") continue;
                foreach (string u in kv.Value.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                {
                    if (u.EndsWith("$")) continue;               // computer account: the host part is already mapped
                    if (_terms.ContainsKey(u) || !IsUserName(u) || u.Length < MinBareTermLength) continue;
                    GetOrCreate(u, "User", "known-host\\user", true);
                }
            }

            // 7) inventory paths: "<vcenter>\<datacenter>\<cluster>\<vm>"
            foreach (string p in _inventoryPaths)
            {
                string[] seg = p.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                if (seg.Length < 2) continue;
                MapEntry fe;
                if (!_terms.TryGetValue(seg[0], out fe)) continue;  // only trust paths rooted on a known host
                if (fe.Category != "FQDN" && fe.Category != "Host") continue;
                for (int i = 1; i < seg.Length; i++)
                {
                    string s = seg[i].Trim();
                    if (!IsObjectName(s) || s.Length < MinBareTermLength) continue;
                    if (_terms.ContainsKey(s)) continue;
                    GetOrCreate(s, i == seg.Length - 1 ? "VM" : "Inventory", "inventory-path", true);
                }
            }

            BuildTrie();
            _finalized = true;
        }

        private static IEnumerable<string> Variants(string term)
        {
            yield return term;
            if (term.IndexOf(' ') >= 0)
            {
                yield return term.Replace(' ', '_');
                yield return term.Replace(" ", "%20");
                yield return term.Replace(' ', '+');
            }
            if (term.IndexOf('-') >= 0)
            {
                yield return term.Replace("-", "_B");      // Veeam file-name escaping
                if (term.IndexOf(' ') >= 0) yield return term.Replace(' ', '_').Replace("-", "_B");
            }
            if (term.IndexOf('_') >= 0) yield return term.Replace('_', ' ');
            // "ubuntu02 Backup" -> mutex / object names such as "ubuntu02backup"
            string squashed = term.Replace(" ", "").Replace("_", "");
            if (squashed.Length >= 8 && squashed.Length != term.Length) yield return squashed;
            if (term.IndexOf('.') >= 0 && term.IndexOf(' ') < 0 && term.IndexOf('.') != term.Length - 1) { /* FQDN variants handled by trie */ }
        }

        private void BuildTrie()
        {
            // substring terms: reuse an existing placeholder when the same value was discovered as a name
            foreach (MapEntry e in _substringTerms)
            {
                MapEntry existing;
                if (e.Fake == null && _terms.TryGetValue(e.Original, out existing)) e.Fake = existing.Fake;
                if (e.Fake == null) e.Fake = NextFake("Custom");
                if (!_terms.ContainsKey(e.Original)) _terms[e.Original] = e;
            }
            if (_substringTerms.Count > 0)
                _substringRx = new Regex(string.Join("|", _substringTerms.OrderByDescending(x => x.Original.Length).Select(x => Regex.Escape(x.Original))), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
            _trie = new Trie();
            // longer originals first is not needed (trie takes the longest match), but priority matters on collisions
            foreach (MapEntry e in _terms.Values.OrderBy(x => Prio(x.Category == "FQDN" ? "Host" : x.Category)))
            {
                if (!e.Bare) continue;
                if (IsKeep(e.Original)) continue;
                foreach (string v in Variants(e.Original)) _trie.Add(v, e);
            }
        }

        // ================================================================== anonymization
        private static bool IsWordChar(char c) { return char.IsLetterOrDigit(c); }

        private static readonly string[] JoinedSuffixes = { "veeamworker", "veeamproxy", "worker", "proxy", "backup", "replica" };
        private static readonly Regex RxDateJoin = new Regex(@"\GD\d{4}-\d{2}-\d{2}T\d", RegexOptions.Compiled);

        // a name ending with a digit directly followed by another token: "srv-app03D2026-09-15T13...vbk",
        // "srv-app01Administrator", "esx2veeamworker"
        private static bool JoinedSuffixOk(string text, int lastIdx, int end)
        {
            if (!char.IsDigit(text[lastIdx]) || end >= text.Length) return false;
            if (lastIdx < 3) return false;
            char c = text[end];
            if (c == 'D' && RxDateJoin.IsMatch(text, end)) return true;
            if (char.IsUpper(c) && end + 1 < text.Length && char.IsLower(text[end + 1])) return true;
            foreach (string s in JoinedSuffixes)
                if (string.Compare(text, end, s, 0, s.Length, StringComparison.OrdinalIgnoreCase) == 0 &&
                    (end + s.Length >= text.Length || !char.IsLetterOrDigit(text[end + s.Length]))) return true;
            return false;
        }

        private static bool IsTruncationTail(string text, int j)
        {
            if (j + 5 > text.Length || text[j] != '_') return false;
            for (int k = j + 1; k < j + 5; k++) if (!char.IsLetterOrDigit(text[k])) return false;
            return j + 5 == text.Length || !char.IsLetterOrDigit(text[j + 5]);
        }

        private static string CaseLike(string occurrence, string fake)
        {
            bool hasLetter = false, allUpper = true;
            foreach (char c in occurrence)
            {
                if (char.IsLetter(c)) { hasLetter = true; if (!char.IsUpper(c)) { allUpper = false; break; } }
            }
            if (hasLetter && allUpper) return fake.ToUpperInvariant();
            return fake;
        }

        private string ReplaceTerms(string text, Trie trie, bool countHits)
        {
            if (trie == null || trie.Count == 0 || string.IsNullOrEmpty(text)) return text;
            StringBuilder sb = null;
            int n = text.Length, last = 0, i = 0;
            Dictionary<char, TrieNode> rootNext = trie.Root.Next;
            if (rootNext == null) return text;
            while (i < n)
            {
                if (i > 0 && IsWordChar(text[i - 1])) { i++; continue; }
                TrieNode node;
                if (!rootNext.TryGetValue(char.ToLowerInvariant(text[i]), out node)) { i++; continue; }
                int j = i; MapEntry best = null; int bestEnd = -1;
                while (true)
                {
                    if (node.Entry != null)
                    {
                        int end = j + 1;
                        if (end >= n || !IsWordChar(text[end]) || !IsWordChar(text[j]) || (countHits && JoinedSuffixOk(text, j, end))) { best = node.Entry; bestEnd = end; }
                    }
                    j++;
                    if (j >= n || node.Next == null) break;
                    TrieNode nx;
                    if (!node.Next.TryGetValue(char.ToLowerInvariant(text[j]), out nx))
                    {
                        // Veeam truncates long names and appends "_XXXX": "s3-offsite-veeamrep_x7kq"
                        if (best == null && countHits && j - i >= 12 && node.AnyCount == 1 && node.Any != null && IsTruncationTail(text, j))
                        { best = node.Any; bestEnd = j; }
                        break;
                    }
                    node = nx;
                }
                if (best != null)
                {
                    if (sb == null) sb = new StringBuilder(n + 64);
                    sb.Append(text, last, i - last);
                    sb.Append(CaseLike(text.Substring(i, bestEnd - i), best.Fake));
                    if (countHits) { best.Hits++; }
                    last = bestEnd; i = bestEnd;
                }
                else i++;
            }
            if (sb == null) return text;
            sb.Append(text, last, n - last);
            return sb.ToString();
        }

        private static readonly string[] PublicFakeNets = { "203.0.113", "198.51.100", "192.0.2" };
        private HashSet<string> _realNets;
        private HashSet<string> _versionPrefixes;

        // "13.4.1.3" with no context at all, while "13.4.0.300" / "13.1.1.18" are known versions => version
        private bool LooksLikeVersion(byte[] b)
        {
            if (_versionPrefixes == null)
            {
                _versionPrefixes = new HashSet<string>(StringComparer.Ordinal);
                foreach (KeyValuePair<string, IpStat> kv in _ip)
                    if (kv.Value.Version > 0 && kv.Value.Strong == 0)
                    {
                        string[] p = kv.Key.Split('.');
                        _versionPrefixes.Add(p[0] + "." + p[1]);
                        _versionPrefixes.Add(p[0] + ".*");
                    }
            }
            if (b[0] > 20 || b[1] > 20) return false;
            if (_versionPrefixes.Contains(b[0] + "." + b[1])) return true;
            if ((b[2] == 0 && b[3] == 0) || (_versionPrefixes.Contains(b[0] + ".*") && (b[2] == 0 || b[3] == 0))) return true;
            return false;
        }

        private static bool IsSpecialKeep(byte[] b)
        {
            if (b[0] == 0 || b[0] == 127 || b[0] >= 224) return true;
            if (b[0] == 255) return true;
            return false;
        }

        private static int Kind(byte[] b)
        {
            if (b[0] == 10) return 1;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return 1;
            if (b[0] == 192 && b[1] == 168) return 1;
            if (b[0] == 169 && b[1] == 254) return 2;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return 3;
            return 0; // public
        }

        private string FakeIPv4(string ip, byte[] b)
        {
            MapEntry e;
            if (_fixed.TryGetValue("ip:" + ip, out e)) return e.Fake;
            string net = b[0] + "." + b[1] + "." + b[2];
            MapEntry ne;
            string key = "net:" + net;
            if (!_fixed.TryGetValue(key, out ne))
            {
                if (_realNets == null)
                {
                    _realNets = new HashSet<string>(StringComparer.Ordinal);
                    foreach (string k in _ip.Keys) _realNets.Add(k.Substring(0, k.LastIndexOf('.')));
                }
                int kind = Kind(b);
                string cat = "IPv4Net" + kind;
                string f;
                while (true)
                {
                    int n; _counters.TryGetValue(cat, out n); n++; _counters[cat] = n;
                    if (kind == 1) f = "10." + (200 + (n - 1) / 256) + "." + ((n - 1) % 256);
                    else if (kind == 2) f = "169.254." + ((n - 1) % 256);
                    else if (kind == 3) f = "100.64." + ((n - 1) % 256);
                    else if (n <= PublicFakeNets.Length) f = PublicFakeNets[n - 1];
                    else f = "198.18." + ((n - 1 - PublicFakeNets.Length) % 256);
                    if (n > 5000 || (!_realNets.Contains(f) && !_usedFakes.Contains("net:" + f))) break;   // never map onto a real network
                }
                _usedFakes.Add("net:" + f);
                ne = new MapEntry { Category = "IPv4Network", Original = net, Fake = f };
                _fixed[key] = ne;
            }
            string fake = ne.Fake + "." + b[3];
            e = new MapEntry { Category = "IPv4", Original = ip, Fake = fake };
            _fixed["ip:" + ip] = e;
            return fake;
        }

        private string AnonymizeIPv4(string text)
        {
            if (text.IndexOf('.') < 0) return text;
            StringBuilder sb = null; int last = 0;
            for (Match m = AxIPv4.Match(text); m.Success; m = m.NextMatch())
            {
                string ip = m.Groups["ip"].Value;
                string[] p = ip.Split('.');
                byte[] b = new byte[4];
                for (int k = 0; k < 4; k++) b[k] = (byte)int.Parse(p[k]);
                string repl = ip;
                bool anon;
                if (IsSpecialKeep(b)) anon = false;
                else
                {
                    string pre = Pre(text, m.Index, 40);
                    string post = Post(text, m.Index + m.Length, 8);
                    int kind = Kind(b);
                    bool strong = CtxStrongPre.IsMatch(pre) || CtxStrongPost.IsMatch(post);
                    bool verWord = CtxVersionWord.IsMatch(pre);
                    bool ver = verWord || CtxVersion.IsMatch(pre) || CtxUserAgent.IsMatch(pre);
                    IpStat st; _ip.TryGetValue(ip, out st);
                    if (strong) anon = true;
                    else if (verWord) anon = false;
                    else if (ver && kind == 0) anon = false;
                    else if (st != null && st.Strong > 0) anon = true;
                    else if (st != null && st.Version > 0 && kind == 0) anon = false;
                    else if (st != null && st.VersionWord > 0 && st.Strong == 0) anon = false;
                    else if (kind != 0) anon = true;
                    else if (LooksLikeVersion(b)) anon = false;
                    else anon = AnonymizePublicIPs;
                }
                if (anon) { repl = FakeIPv4(ip, b); Stat("IPv4", 1); }
                else { long v; _keptIpLike.TryGetValue(ip, out v); _keptIpLike[ip] = v + 1; continue; }
                if (sb == null) sb = new StringBuilder(text.Length + 64);
                sb.Append(text, last, m.Index - last).Append(repl);
                last = m.Index + m.Length;
            }
            if (sb == null) return text;
            sb.Append(text, last, text.Length - last);
            return sb.ToString();
        }

        private string ReplaceIPv6(string text)
        {
            if (!AnonymizeIPv6 || text.IndexOf(':') < 0) return text;
            return AxIPv6.Replace(text, delegate (Match m)
            {
                string ip = m.Groups["ip"].Value;
                bool dbl = ip.Contains("::");
                int groups = ip.Split(':').Length;
                if (!dbl && groups != 8) return m.Value;
                IPAddress a;
                if (!IPAddress.TryParse(ip, out a) || a.AddressFamily != AddressFamily.InterNetworkV6) return m.Value;
                if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.IPv6Any) || a.Equals(IPAddress.IPv6None)) return m.Value;
                byte[] by = a.GetAddressBytes();
                bool allZeroExceptLast = true;
                for (int k = 0; k < 15; k++) if (by[k] != 0) { allZeroExceptLast = false; break; }
                if (allZeroExceptLast) return m.Value;
                bool noInterfaceId = true;                       // prefixes such as "fe80::" or "2001:db8::"
                for (int k = 8; k < 16; k++) if (by[k] != 0) { noInterfaceId = false; break; }
                if (noInterfaceId && a.IsIPv6LinkLocal) return m.Value;
                // only hex-ish tokens with a letter or "::" (avoid times such as 12:30:45)
                if (!dbl && !ip.Any(c => (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return m.Value;
                if (ip.StartsWith("::ffff", StringComparison.OrdinalIgnoreCase) && groups <= 3) return m.Value;
                string key = "ip6:" + a.ToString();
                MapEntry e;
                if (!_fixed.TryGetValue(key, out e))
                {
                    int n; _counters.TryGetValue("IPv6", out n); n++; _counters["IPv6"] = n;
                    string prefix = a.IsIPv6LinkLocal ? "fe80::" : "fd00:a0a0::";
                    e = new MapEntry { Category = "IPv6", Original = a.ToString(), Fake = prefix + n.ToString("x") };
                    _fixed[key] = e;
                }
                Stat("IPv6", 1);
                string res = e.Fake;
                if (m.Groups["z"].Success) res += "%" + m.Groups["z"].Value;
                return res;
            });
        }

        private string AnonymizeMacs(string text)
        {
            if (!AnonymizeMac) return text;
            if (text.IndexOf(':') < 0 && text.IndexOf('-') < 0) return text;
            return AxMac.Replace(text, delegate (Match m)
            {
                string sep = m.Groups["sep"].Value;
                string oui = m.Groups["a"].Value + sep + m.Groups["b"].Value + sep + m.Groups["c"].Value;
                string all = m.Value.ToUpperInvariant().Replace('-', ':');
                if (all == "00:00:00:00:00:00" || all == "FF:FF:FF:FF:FF:FF") return m.Value;
                string key = "mac:" + all;
                MapEntry e;
                if (!_fixed.TryGetValue(key, out e))
                {
                    int n; _counters.TryGetValue("MAC", out n); n++; _counters["MAC"] = n;
                    string nic = string.Format("{0:X2}:{1:X2}:{2:X2}", 0xA0, (n >> 8) & 0xFF, n & 0xFF);
                    e = new MapEntry { Category = "MAC", Original = all, Fake = all.Substring(0, 8) + ":" + nic };
                    _fixed[key] = e;
                }
                Stat("MAC", 1);
                string fake = e.Fake.Substring(9).Replace(":", sep);
                bool lower = m.Value.Any(c => c >= 'a' && c <= 'f');
                if (lower) fake = fake.ToLowerInvariant();
                return oui + sep + fake;
            });
        }

        private string AnonymizeSids(string text)
        {
            if (text.IndexOf("S-1-5-21-", StringComparison.Ordinal) < 0) return text;
            return AxSid.Replace(text, delegate (Match m)
            {
                string d = m.Groups["d"].Value;
                string key = "sid:" + d;
                MapEntry e;
                if (!_fixed.TryGetValue(key, out e))
                {
                    int n; _counters.TryGetValue("SID", out n); n++; _counters["SID"] = n;
                    e = new MapEntry { Category = "SID", Original = d, Fake = "1000000000-1000000000-" + (1000000000 + n) };
                    _fixed[key] = e;
                }
                Stat("SID", 1);
                return "S-1-5-21-" + e.Fake;
            });
        }

        private static bool IsPrintable(string s)
        {
            if (s.Length == 0) return false;
            int bad = 0;
            foreach (char c in s)
            {
                if (c == '\r' || c == '\n' || c == '\t') continue;
                if (c < 0x20 || c == 0xFFFD || (c >= 0x7F && c < 0xA0)) bad++;
            }
            return bad == 0;
        }

        private int _b64Depth;
        private static readonly Regex AxJwt = new Regex(@"\beyJ[A-Za-z0-9_-]{4,}\.(?<p>[A-Za-z0-9_-]{4,})\.(?<s>[A-Za-z0-9_-]{8,})", RO);

        private static byte[] FromBase64Loose(string b, bool url)
        {
            string s = url ? b.Replace('-', '+').Replace('_', '/') : b;
            int pad = (4 - s.Length % 4) % 4;
            if (pad == 3) return null;
            s = s + new string('=', pad);
            try { return Convert.FromBase64String(s); } catch { return null; }
        }

        // JWT: anonymize the payload (it often contains "iss": "https://<server>/", user names...) and drop the signature
        private string ReplaceJwt(string text)
        {
            if (text.IndexOf("eyJ", StringComparison.Ordinal) < 0) return text;
            return AxJwt.Replace(text, delegate (Match m)
            {
                string head = m.Value.Substring(0, m.Groups["p"].Index - m.Index);
                byte[] raw = FromBase64Loose(m.Groups["p"].Value, true);
                string payload = m.Groups["p"].Value;
                if (raw != null)
                {
                    string dec;
                    try { dec = new UTF8Encoding(false, true).GetString(raw); } catch { dec = null; }
                    if (dec != null && IsPrintable(dec))
                    {
                        _b64Depth++;
                        string anon;
                        try { anon = AnonymizeCore(dec); } finally { _b64Depth--; }
                        payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(anon)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                    }
                }
                Stat("JWT", 1);
                return head + payload + ".REDACTED-SIGNATURE";
            });
        }

        private string ReplaceBase64(string text)
        {
            if (!AnonymizeBase64 || _b64Depth > 1) return text;
            text = ReplaceJwt(text);
            return AxBase64.Replace(text, delegate (Match m)
            {
                string b = m.Groups["b"].Value;
                bool padded = b.EndsWith("=");
                if (b.Length % 4 == 1) return m.Value;
                if (padded && b.Length % 4 != 0) return m.Value;
                // require some mix to skip plain long words
                bool hasDigitOrSym = b.Any(c => char.IsDigit(c) || c == '+' || c == '/' || c == '=');
                bool hasUpper = b.Any(char.IsUpper), hasLower = b.Any(char.IsLower);
                if (!hasDigitOrSym || !(hasUpper && hasLower)) return m.Value;
                byte[] raw = FromBase64Loose(b, false);
                if (raw == null || raw.Length < 4) return m.Value;
                string dec = null; Encoding enc = null;
                try
                {
                    UTF8Encoding strict = new UTF8Encoding(false, true);
                    string s = strict.GetString(raw);
                    if (IsPrintable(s)) { dec = s; enc = new UTF8Encoding(false); }
                }
                catch { }
                if (dec == null && raw.Length >= 4 && raw.Length % 2 == 0)
                {
                    int zeros = 0; for (int k = 1; k < raw.Length; k += 2) if (raw[k] == 0) zeros++;
                    if (zeros * 2 >= raw.Length * 0.9 / 1)
                    {
                        string s = Encoding.Unicode.GetString(raw);
                        if (IsPrintable(s)) { dec = s; enc = Encoding.Unicode; }
                    }
                }
                if (dec == null) return m.Value;
                _b64Depth++;
                string anon;
                try { anon = AnonymizeCore(dec); } finally { _b64Depth--; }
                if (anon == dec) return m.Value;
                Stat("Base64", 1);
                string res = Convert.ToBase64String(enc.GetBytes(anon));
                return (padded || b.Length % 4 == 0) ? res : res.TrimEnd('=');
            });
        }

        // ---------------------------------------------------------------- substring terms (opt-in, e.g. a customer name)
        private readonly List<MapEntry> _substringTerms = new List<MapEntry>();
        private Regex _substringRx;

        public void AddSubstringTerm(string original, string fake)
        {
            if (string.IsNullOrWhiteSpace(original) || original.Trim().Length < 3) return;
            original = original.Trim();
            MapEntry e = new MapEntry { Category = "Custom", Original = original, Bare = true, Source = "config-substring" };
            e.Fake = string.IsNullOrWhiteSpace(fake) ? null : fake.Trim();
            _substringTerms.Add(e);
        }

        private string ReplaceSubstringTerms(string text)
        {
            if (_substringRx == null) return text;
            return _substringRx.Replace(text, delegate (Match m)
            {
                foreach (MapEntry e in _substringTerms)
                    if (string.Equals(e.Original, m.Value, StringComparison.OrdinalIgnoreCase)) { e.Hits++; return CaseLike(m.Value, e.Fake); }
                return m.Value;
            });
        }

        private string AnonymizeCore(string text)
        {
            string t = ReplaceTerms(text, _trie, true);
            t = ReplaceSubstringTerms(t);
            t = AnonymizeIPv4(t);
            t = ReplaceIPv6(t);
            t = AnonymizeMacs(t);
            t = AnonymizeSids(t);
            return t;
        }

        // PEM blocks (private keys, certificates, CSRs, public keys). The body spans several lines, which
        // Veeam writes in different ways: real newlines with the log prefix repeated on every line
        // ("[date] < tid> cli      | MIIH..."), "~n" escapes, "\n" in JSON, XML entities, or spaces.
        // Only the base64 lines are removed: prefixes and separators are kept so the log layout survives.
        private const string PemSep = @"\r?\n(?:\[[^\]\r\n]{5,40}\][^|\r\n]{0,60}\|[ \t]?)?|\\r\\n|\\n|~r~n|~n|&#13;&#10;|&#10;|&#xD;&#xA;|&#xA;|[ \t]+";
        private static readonly Regex AxPemSplit = new Regex("(" + PemSep + ")", RegexOptions.Compiled);
        private static readonly Regex AxPem = new Regex(@"-----BEGIN (?<l>[A-Z0-9 ]{3,40})-----(?<b>(?>(?:Proc-Type|DEK-Info|Comment):[^\r\n\\~]*|" + PemSep + @"|[A-Za-z0-9+/=]+){0,20000}?)-----END \k<l>-----", RO);
        private static readonly Regex AxPemOpen = new Regex(@"-----BEGIN (?<l>[A-Z0-9 ]{3,40})-----(?<b>(?>(?:" + PemSep + @")?[A-Za-z0-9+/=]{16,}){1,1000}(?>(?:" + PemSep + @")?[A-Za-z0-9+/=]{1,15})?)(?![A-Za-z0-9+/=])", RO);   // truncated block (no END line)
        private static readonly Regex RxPemToken = new Regex(@"^[A-Za-z0-9+/=]+$", RegexOptions.Compiled);

        private string ReplacePem(string text)
        {
            if (text.IndexOf("-----BEGIN ", StringComparison.Ordinal) < 0 && text.IndexOf("MII", StringComparison.Ordinal) < 0) return text;
            MatchEvaluator ev = delegate (Match m)
            {
                string label = m.Groups["l"].Value;
                string body = m.Groups["b"].Value;
                string[] parts = AxPemSplit.Split(body);       // even index = content, odd index = separator
                StringBuilder sb = new StringBuilder();
                bool marked = false, changed = false;
                string pendingSep = "";
                for (int i = 0; i < parts.Length; i++)
                {
                    string p = parts[i];
                    if (i % 2 == 1) { pendingSep += p; continue; }
                    if (p.Length > 0 && RxPemToken.IsMatch(p))
                    {
                        changed = true;
                        if (marked) { pendingSep = ""; continue; }   // drop the line together with its separator
                        sb.Append(pendingSep).Append("REDACTED-PEM-").Append(label.Replace(' ', '-'));
                        pendingSep = ""; marked = true;
                        continue;
                    }
                    sb.Append(pendingSep).Append(p); pendingSep = "";
                }
                // a separator before "-----END" (e.g. the log prefix of the END line) belongs to the layout
                if (m.Value.EndsWith("-----", StringComparison.Ordinal) && m.Groups["b"].Index + m.Groups["b"].Length < m.Index + m.Length)
                    sb.Append(pendingSep);
                if (!changed) return m.Value;
                Stat(label.IndexOf("PRIVATE", StringComparison.Ordinal) >= 0 ? "PEM private key" : "PEM block", 1);
                string nb = sb.ToString();
                string end = m.Value.Substring(m.Groups["b"].Index - m.Index + m.Groups["b"].Length);
                return "-----BEGIN " + label + "-----" + nb + end;
            };
            string t = text;
            if (t.IndexOf("-----BEGIN ", StringComparison.Ordinal) >= 0)
            {
                t = AxPem.Replace(t, ev);
                if (t.IndexOf("-----BEGIN ", StringComparison.Ordinal) >= 0) t = AxPemOpen.Replace(t, ev);
            }
            if (t.IndexOf("MII", StringComparison.Ordinal) >= 0)
            {
                // DER certificates / keys without PEM markers (e.g. VDDK "...with certificate" followed by base64 lines)
                t = AxDerLines.Replace(t, delegate (Match m) { Stat("DER certificate/key", 1); return m.Groups["p"].Value + "REDACTED-DER-BLOB"; });
                t = AxDerInline.Replace(t, delegate (Match m) { Stat("DER certificate/key", 1); return "REDACTED-DER-BLOB"; });
            }
            return t;
        }

        // "MII" = ASN.1 SEQUENCE with a two-byte length: the start of almost every base64 certificate or private key
        private static readonly Regex AxDerLines = new Regex(@"(?m)^(?<p>[^\r\n]{0,120}?(?:\|[ \t]?(?:\[vddk\][ \t])?|[ \t]))MII[A-Za-z0-9+/]{40,76}={0,2}[ \t]*(?:\r?\n[^\r\n]{0,120}?\|[ \t]?(?:\[vddk\][ \t])?(?:[A-Za-z0-9+/]{16,76}={0,2}|[A-Za-z0-9+/]{2,15}={1,2})[ \t]*(?=\r?\n|$))+", RO);
        private static readonly Regex AxDerInline = new Regex(@"(?<![A-Za-z0-9+/=])MII[A-Za-z0-9+/]{100,65536}={0,2}(?![A-Za-z0-9+/=])", RO);

        public string AnonymizeText(string text)
        {
            if (!_finalized) throw new InvalidOperationException("FinalizeDiscovery() must be called first");
            if (string.IsNullOrEmpty(text)) return text;
            string t = ReplacePem(text);
            t = ReplaceBase64(t);
            return AnonymizeCore(t);
        }

        public string AnonymizeRelativePath(string relPath)
        {
            string[] seg = relPath.Split(new[] { '\\', '/' });
            for (int i = 0; i < seg.Length; i++) if (seg[i].Length > 0) seg[i] = AnonymizeCore(seg[i]);
            return string.Join("\\", seg);
        }

        // ================================================================== leak check
        private Trie _leakTrie;
        private readonly Dictionary<MapEntry, LeakInfo> _leaks = new Dictionary<MapEntry, LeakInfo>();

        public void PrepareLeakCheck(int minLen)
        {
            _leakTrie = new Trie();
            IEnumerable<MapEntry> all = _terms.Values.Concat(_fixed.Values.Where(e => e.Category == "IPv4" || e.Category == "IPv6"));
            foreach (MapEntry e in all)
            {
                if (e.Original.Length < minLen) continue;
                if (IsKeep(e.Original)) continue;
                if (e.Category == "Domain" && !e.Bare) continue;
                if (!e.Bare && e.Category != "IPv4" && e.Category != "IPv6") continue;
                _leakTrie.Add(e.Original, e);
            }
        }

        // substring search (no word boundaries) so that partial leaks are reported too
        public void LeakScan(string text, string fileLabel)
        {
            if (_leakTrie == null || string.IsNullOrEmpty(text)) return;
            Dictionary<char, TrieNode> root = _leakTrie.Root.Next;
            if (root == null) return;
            int n = text.Length;
            for (int i = 0; i < n; i++)
            {
                TrieNode node;
                if (!root.TryGetValue(char.ToLowerInvariant(text[i]), out node)) continue;
                int j = i;
                MapEntry hit = null; int hitEnd = 0;
                while (true)
                {
                    if (node.Entry != null) { hit = node.Entry; hitEnd = j + 1; }
                    j++;
                    if (j >= n || node.Next == null) break;
                    TrieNode nx;
                    if (!node.Next.TryGetValue(char.ToLowerInvariant(text[j]), out nx)) break;
                    node = nx;
                }
                if (hit == null) continue;
                // IPs: require numeric boundaries to avoid "192.168.0.1" matching inside "192.168.0.10"
                if (hit.Category == "IPv4" || hit.Category == "IPv6")
                {
                    bool okL = i == 0 || !(char.IsDigit(text[i - 1]) || text[i - 1] == '.');
                    bool okR = hitEnd >= n || !(char.IsDigit(text[hitEnd]) || (text[hitEnd] == '.' && hitEnd + 1 < n && char.IsDigit(text[hitEnd + 1])));
                    if (!okL || !okR) continue;
                }
                LeakInfo li;
                int s0 = Math.Max(0, i - 50), e0 = Math.Min(n, hitEnd + 50);
                if (!_leaks.TryGetValue(hit, out li))
                {
                    li = new LeakInfo { Original = hit.Original, Category = hit.Category, FirstFile = fileLabel, Sample = text.Substring(s0, e0 - s0).Replace("\r", " ").Replace("\n", " ") };
                    _leaks[hit] = li;
                }
                li.Count++;
                bool whole = (i == 0 || !IsWordChar(text[i - 1])) && (hitEnd >= n || !IsWordChar(text[hitEnd]));
                if (whole)
                {
                    li.WholeWord++;
                    if (li.WholeSample == null) { li.WholeSample = text.Substring(s0, e0 - s0).Replace("\r", " ").Replace("\n", " "); li.FirstFile = fileLabel; }
                }
                else li.Partial++;
                i = hitEnd - 1;
            }
        }

        public LeakInfo[] GetLeaks() { return _leaks.Values.OrderByDescending(l => l.WholeWord).ThenByDescending(l => l.Count).ToArray(); }

        // ================================================================== reverse (de-anonymize)
        private Trie _reverseTrie;
        public void PrepareReverse()
        {
            _reverseTrie = new Trie();
            foreach (MapEntry e in _terms.Values.Concat(_fixed.Values).OrderBy(x => x.Category == "FQDN" ? 0 : 1))
            {
                if (e.Category == "IPv4Network" || e.Category == "SID" || e.Category == "MAC") continue;
                MapEntry r = new MapEntry { Category = e.Category, Original = e.Fake, Fake = e.Original, Bare = true };
                _reverseTrie.Add(e.Fake, r);
            }
            // SIDs and MACs
            foreach (MapEntry e in _fixed.Values)
            {
                if (e.Category == "SID") _reverseTrie.Add("S-1-5-21-" + e.Fake, new MapEntry { Category = "SID", Original = e.Fake, Fake = "S-1-5-21-" + e.Original });
                if (e.Category == "MAC") { _reverseTrie.Add(e.Fake, new MapEntry { Category = "MAC", Original = e.Fake, Fake = e.Original }); _reverseTrie.Add(e.Fake.Replace(':', '-'), new MapEntry { Category = "MAC", Original = e.Fake, Fake = e.Original.Replace(':', '-') }); }
            }
        }

        public string RestoreText(string text)
        {
            if (_reverseTrie == null) PrepareReverse();
            return ReplaceTerms(text, _reverseTrie, false);
        }

        // ================================================================== mapping persistence (TSV)
        public void SaveMapping(string path)
        {
            using (StreamWriter w = new StreamWriter(path, false, new UTF8Encoding(true)))
            {
                w.WriteLine("# VeeamLogAnonymizer mapping - PRIVATE: contains the real names. Do NOT share this file.");
                w.WriteLine("Category\tOriginal\tAnonymized\tBare\tHits\tSource");
                foreach (MapEntry e in _terms.Values.OrderBy(x => Prio(x.Category)).ThenBy(x => x.Category).ThenBy(x => x.Fake, StringComparer.Ordinal))
                    w.WriteLine(string.Join("\t", new[] { e.Category, e.Original, e.Fake, e.Bare ? "1" : "0", e.Hits.ToString(), e.Source ?? "" }));
                foreach (MapEntry e in _fixed.Values.OrderBy(x => x.Category).ThenBy(x => x.Fake, StringComparer.Ordinal))
                    w.WriteLine(string.Join("\t", new[] { e.Category, e.Original, e.Fake, "1", "", "" }));
            }
        }

        public int LoadMapping(string path)
        {
            int count = 0;
            foreach (string line in File.ReadAllLines(path))
            {
                if (line.StartsWith("#") || line.StartsWith("Category\t") || line.Trim().Length == 0) continue;
                string[] p = line.Split('\t');
                if (p.Length < 3) continue;
                string cat = p[0], o = p[1], f = p[2];
                bool bare = p.Length < 4 || p[3] != "0";
                MapEntry e = new MapEntry { Category = cat, Original = o, Fake = f, Bare = bare, Source = "mapping" };
                _usedFakes.Add(f);
                if (cat == "IPv4") _fixed["ip:" + o] = e;
                else if (cat == "IPv4Network") _fixed["net:" + o] = e;
                else if (cat == "IPv6") _fixed["ip6:" + o] = e;
                else if (cat == "MAC") _fixed["mac:" + o] = e;
                else if (cat == "SID") _fixed["sid:" + o] = e;
                else _terms[o] = e;
                // keep counters ahead of loaded fakes
                Match m = Regex.Match(f, @"(\d+)$");
                if (m.Success)
                {
                    int num; string ck = cat;
                    if (cat == "IPv4Network") { continue; }
                    if (int.TryParse(m.Groups[1].Value, out num))
                    {
                        int cur; _counters.TryGetValue(ck, out cur);
                        if (num > cur && num < 1000000) _counters[ck] = num;
                    }
                }
                count++;
            }
            // recompute network counters
            foreach (MapEntry e in _fixed.Values.Where(x => x.Category == "IPv4Network"))
            {
                string[] p = e.Original.Split('.');
                byte[] b = { byte.Parse(p[0]), byte.Parse(p[1]), byte.Parse(p[2]), 0 };
                string ck = "IPv4Net" + Kind(b);
                int cur; _counters.TryGetValue(ck, out cur); _counters[ck] = cur + 1;
            }
            return count;
        }

        public void MarkFinalizedForReverse() { _finalized = true; }

        // ================================================================== files
        public static FileText ReadText(string path)
        {
            byte[] data = File.ReadAllBytes(path);
            FileText ft = new FileText();
            if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) { ft.Encoding = new UTF8Encoding(true); ft.Text = new UTF8Encoding(false).GetString(data, 3, data.Length - 3); return ft; }
            if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE) { ft.Encoding = new UnicodeEncoding(false, true); ft.Text = Encoding.Unicode.GetString(data, 2, data.Length - 2); return ft; }
            if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF) { ft.Encoding = new UnicodeEncoding(true, true); ft.Text = Encoding.BigEndianUnicode.GetString(data, 2, data.Length - 2); return ft; }
            int probe = Math.Min(data.Length, 65536), zeros = 0;
            for (int i = 0; i < probe; i++) if (data[i] == 0) zeros++;
            if (zeros > 0)
            {
                // UTF-16 LE without BOM?
                int oddZeros = 0; for (int i = 1; i < probe; i += 2) if (data[i] == 0) oddZeros++;
                if (probe > 16 && oddZeros > probe / 2 * 0.8) { ft.Encoding = new UnicodeEncoding(false, false); ft.Text = Encoding.Unicode.GetString(data); return ft; }
                if (zeros > probe / 100 + 1) { ft.Binary = true; return ft; }
            }
            try { ft.Text = new UTF8Encoding(false, true).GetString(data); ft.Encoding = new UTF8Encoding(false); }
            catch (DecoderFallbackException)
            {
                Encoding latin1 = Encoding.GetEncoding(28591);   // byte-preserving round trip
                ft.Text = latin1.GetString(data); ft.Encoding = latin1;
            }
            return ft;
        }

        public void DiscoverFile(string path)
        {
            FileText ft = ReadText(path);
            if (ft.Binary) { Stat("BinaryFilesSkipped", 1); return; }
            DiscoverText(ft.Text);
        }

        /// returns false if the file is binary (copied unchanged)
        public bool AnonymizeFile(string src, string dst)
        {
            FileText ft = ReadText(src);
            string dir = Path.GetDirectoryName(dst);
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            if (ft.Binary) { File.Copy(src, dst, true); Stat("BinaryFilesCopied", 1); return false; }
            string outText = AnonymizeText(ft.Text);
            using (FileStream fs = new FileStream(dst, FileMode.Create, FileAccess.Write))
            {
                byte[] pre = ft.Encoding.GetPreamble();
                if (pre.Length > 0) fs.Write(pre, 0, pre.Length);
                byte[] body = ft.Encoding.GetBytes(outText);
                fs.Write(body, 0, body.Length);
            }
            Stat("FilesAnonymized", 1);
            return true;
        }

        public void LeakScanFile(string path, string label)
        {
            FileText ft = ReadText(path);
            if (ft.Binary) return;
            LeakScan(ft.Text, label);
        }

        // ================================================================== reporting
        public MapEntry[] GetTerms() { return _terms.Values.OrderBy(x => Prio(x.Category)).ThenBy(x => x.Fake, StringComparer.Ordinal).ToArray(); }
        public MapEntry[] GetFixed() { return _fixed.Values.OrderBy(x => x.Category).ThenBy(x => x.Fake, StringComparer.Ordinal).ToArray(); }
        public Candidate[] GetCandidates() { return _cand.Values.OrderBy(x => Prio(x.Category)).ThenByDescending(x => x.Count).ToArray(); }
        public string[] GetSuffixes() { return _suffixes.OrderBy(x => x).ToArray(); }
        public Dictionary<string, long> GetStats() { return new Dictionary<string, long>(_stats); }

        public KeyValuePair<string, long>[] GetKeptIpLike()
        {
            return _keptIpLike.OrderByDescending(k => k.Value).ToArray();
        }

        public KeyValuePair<string, long>[] GetPublicIpsAnonymizedWithoutContext()
        {
            List<KeyValuePair<string, long>> r = new List<KeyValuePair<string, long>>();
            foreach (MapEntry e in _fixed.Values.Where(x => x.Category == "IPv4"))
            {
                string[] p = e.Original.Split('.');
                byte[] b = { byte.Parse(p[0]), byte.Parse(p[1]), byte.Parse(p[2]), byte.Parse(p[3]) };
                if (Kind(b) != 0) continue;
                IpStat st; _ip.TryGetValue(e.Original, out st);
                if (st == null || st.Strong == 0) r.Add(new KeyValuePair<string, long>(e.Original, st == null ? 0 : st.Total));
            }
            return r.OrderByDescending(x => x.Value).ToArray();
        }
    }
}
