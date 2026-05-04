# ============================================================
# AD enumeration v3 - IIPL.COM
# Native PowerShell / .NET DirectoryServices only
# No external module imports, no flagged literal strings
# Throttled (default 1.5s between sections) to stay close to v2's behavioral footprint
# Output:  .\ad_enum_v3.txt   (clean results)
# Errors:  .\ad_enum_v3.err   (per-section errors, surfaced not swallowed)
# Run:     powershell -ep bypass -nop -f .\iipl_enum_v3.ps1
# ============================================================

$ErrorActionPreference = 'Continue'
$out      = ".\ad_enum_v3.txt"
$err      = ".\ad_enum_v3.err"
$domain   = "IIPL.COM"
$baseDN   = "DC=IIPL,DC=COM"
$throttleMs = 1500

# Discover config / schema DNs once
$rootDSE     = [ADSI]"LDAP://RootDSE"
$configDN    = $rootDSE.configurationNamingContext.ToString()
$schemaDN    = $rootDSE.schemaNamingContext.ToString()
$forestDN    = $rootDSE.rootDomainNamingContext.ToString()

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
function W { param([string]$s) $s | Out-File -FilePath $out -Append -Encoding utf8 }
function Section { param([string]$t)
    W ""; W ("=" * 80); W "  $t"; W ("=" * 80)
    Start-Sleep -Milliseconds $throttleMs
}
function LogErr { param([string]$where, $e)
    "[ERR] $where | $($e.Exception.Message)" | Out-File -FilePath $err -Append
}

function Q {
    param(
        [string]$Filter,
        [string[]]$Props = @(),
        [string]$SearchBase = $baseDN,
        [string]$Where = "unknown"
    )
    try {
        $de = [ADSI]"LDAP://$SearchBase"
        $ds = New-Object DirectoryServices.DirectorySearcher($de)
        $ds.Filter   = $Filter
        $ds.PageSize = 1000
        $ds.SizeLimit = 0
        if ($Props.Count -gt 0) { $Props | ForEach-Object { [void]$ds.PropertiesToLoad.Add($_) } }
        return $ds.FindAll()
    } catch { LogErr $Where $_; return @() }
}

function P { # property accessor
    param($entry, [string]$key, $default = "")
    if ($entry.Properties.Contains($key) -and $entry.Properties[$key].Count -gt 0) {
        return $entry.Properties[$key][0]
    }
    return $default
}
function PJ { # property join (multi-valued)
    param($entry, [string]$key, [string]$sep = "; ")
    if ($entry.Properties.Contains($key) -and $entry.Properties[$key].Count -gt 0) {
        return ($entry.Properties[$key] -join $sep)
    }
    return ""
}

function DecodeUAC {
    param([int64]$uac)
    $f = @()
    if ($uac -band 0x000002)  { $f += "DISABLED" }
    if ($uac -band 0x000010)  { $f += "LOCKOUT" }
    if ($uac -band 0x000020)  { $f += "PASSWD_NOTREQD" }
    if ($uac -band 0x000040)  { $f += "PASSWD_CANT_CHANGE" }
    if ($uac -band 0x000080)  { $f += "ENC_TXT_PWD_OK" }
    if ($uac -band 0x010000)  { $f += "DONT_EXPIRE_PASSWD" }
    if ($uac -band 0x040000)  { $f += "SMARTCARD_REQUIRED" }
    if ($uac -band 0x080000)  { $f += "TRUSTED_FOR_DELEG" }
    if ($uac -band 0x100000)  { $f += "NOT_DELEGATED" }
    if ($uac -band 0x400000)  { $f += "DONT_REQ_PREAUTH" }
    if ($uac -band 0x1000000) { $f += "TRUSTED_TO_AUTH_FOR_DELEG" }
    return ($f -join ",")
}

function FileTimeToString {
    param($ft)
    try {
        if ($null -eq $ft -or $ft -eq 0 -or $ft -eq "") { return "Never" }
        $i64 = [int64]$ft
        if ($i64 -le 0) { return "Never" }
        return [DateTime]::FromFileTime($i64).ToString("u")
    } catch { return "?" }
}

# Recursive group expansion (RFC 4515 LDAP_MATCHING_RULE_IN_CHAIN)
function GroupMembersRecursive {
    param([string]$groupDN)
    $f = "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$groupDN))"
    return Q -Filter $f -Props @("sAMAccountName","displayName","userAccountControl","memberOf","objectSid","servicePrincipalName") -Where "RecGrpExpand"
}

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------
"=" * 80                                       | Out-File $out -Encoding utf8
"  AD ENUMERATION v3 - $domain"                | Out-File $out -Append -Encoding utf8
"  Run on: $env:COMPUTERNAME by $env:USERDOMAIN\$env:USERNAME"  | Out-File $out -Append -Encoding utf8
"  Date: $(Get-Date)"                          | Out-File $out -Append -Encoding utf8
"  configDN: $configDN"                        | Out-File $out -Append -Encoding utf8
"  forestDN: $forestDN"                        | Out-File $out -Append -Encoding utf8
"=" * 80                                       | Out-File $out -Append -Encoding utf8

# ------------------------------------------------------------
# 0. Current user context (baseline)
# ------------------------------------------------------------
Section "0. CURRENT USER CONTEXT"
whoami /all 2>&1 | Out-File $out -Append
W "`n--- Local groups membership for $env:USERNAME ---"
net user $env:USERNAME /domain 2>&1 | Out-File $out -Append
W "`n--- Local admin on this host? ---"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
W "Local admin: $isAdmin"

# ------------------------------------------------------------
# 1. Domain / forest summary
# ------------------------------------------------------------
Section "1. DOMAIN & FOREST"
try {
    $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    W "Domain:         $($dom.Name)"
    W "DomainMode:     $($dom.DomainMode)"
    W "PDC:            $($dom.PdcRoleOwner)"
    W "Forest:         $($dom.Forest.Name)"
    W "ForestMode:     $($dom.Forest.ForestMode)"
    W "DC list:"
    $dom.DomainControllers | ForEach-Object { W "  - $($_.Name) | Site: $($_.SiteName) | OS: $($_.OSVersion) | IP: $($_.IPAddress)" }
} catch { LogErr "1.DomainForest" $_ }

# ------------------------------------------------------------
# 2. Sites & subnets
# ------------------------------------------------------------
Section "2. SITES & SUBNETS"
$sites = Q -Filter "(objectClass=site)" -SearchBase "CN=Sites,$configDN" -Props @("cn","siteObjectBL") -Where "Sites"
foreach ($s in $sites) { W ("Site: " + (P $s "cn")) }
$subs = Q -Filter "(objectClass=subnet)" -SearchBase "CN=Subnets,CN=Sites,$configDN" -Props @("cn","siteObject","description") -Where "Subnets"
foreach ($s in $subs) { W ("Subnet: " + (P $s "cn") + " | Site: " + (P $s "siteObject") + " | " + (P $s "description")) }

# ------------------------------------------------------------
# 3. Trusts
# ------------------------------------------------------------
Section "3. TRUSTS"
$trusts = Q -Filter "(objectClass=trustedDomain)" -Props @("cn","trustDirection","trustType","trustAttributes","trustPartner","flatName") -Where "Trusts"
if ($trusts.Count -eq 0) { W "No trusts found" }
foreach ($t in $trusts) {
    $dirN = [int](P $t "trustDirection" 0)
    $dir  = switch ($dirN) { 1 {"Inbound"} 2 {"Outbound"} 3 {"Bidirectional"} default {"Unknown($dirN)"} }
    W ("Trust: " + (P $t "cn") + " | Partner: " + (P $t "trustPartner") + " | Direction: $dir | Type: " + (P $t "trustType") + " | Attrs: " + (P $t "trustAttributes"))
}

# ------------------------------------------------------------
# 4. Password policy
# ------------------------------------------------------------
Section "4. PASSWORD POLICY (default + fine-grained)"
net accounts /domain 2>&1 | Out-File $out -Append
W "`n--- Fine-grained password policies ---"
$fgpp = Q -Filter "(objectClass=msDS-PasswordSettings)" -SearchBase "CN=Password Settings Container,CN=System,$baseDN" `
        -Props @("cn","msds-passwordsettingsprecedence","msds-minimumpasswordlength","msds-passwordhistorylength","msds-lockoutthreshold","msds-passwordcomplexityenabled","msds-psoappliesto") -Where "FGPP"
if ($fgpp.Count -eq 0) { W "None" }
foreach ($p in $fgpp) {
    W ("FGPP: " + (P $p "cn") + " | Precedence: " + (P $p "msds-passwordsettingsprecedence") +
       " | MinLen: " + (P $p "msds-minimumpasswordlength") + " | History: " + (P $p "msds-passwordhistorylength") +
       " | Lockout: " + (P $p "msds-lockoutthreshold") + " | AppliesTo: " + (PJ $p "msds-psoappliesto"))
}

# ------------------------------------------------------------
# 5. Privileged groups (membership, recursive)
# ------------------------------------------------------------
Section "5. PRIVILEGED GROUP MEMBERSHIP (recursive)"
$privGroups = @(
    "Domain Admins","Enterprise Admins","Schema Admins","Administrators",
    "Account Operators","Server Operators","Backup Operators","Print Operators",
    "DnsAdmins","Cert Publishers","Group Policy Creator Owners","Protected Users",
    "Remote Desktop Users","Remote Management Users","Hyper-V Administrators",
    "Event Log Readers","Distributed COM Users","Cryptographic Operators"
)
foreach ($g in $privGroups) {
    $gres = Q -Filter "(&(objectCategory=group)(cn=$g))" -Props @("distinguishedName","member","objectSid") -Where "Group:$g"
    if ($gres.Count -eq 0) { W "$g : (group not found in this domain)"; continue }
    $gDN = (P $gres[0] "distinguishedName")
    $members = GroupMembersRecursive $gDN
    W "`n=== $g ($($members.Count) recursive members) ==="
    foreach ($m in $members) {
        $sam  = (P $m "sAMAccountName")
        $disp = (P $m "displayName")
        $uac  = [int64](P $m "userAccountControl" 0)
        $flag = DecodeUAC $uac
        $spn  = PJ $m "servicePrincipalName"
        W "  $sam | $disp | UAC:$flag | SPN:$spn"
    }
}

# ------------------------------------------------------------
# 6. AdminCount=1 accounts (often forgotten privileged)
# ------------------------------------------------------------
Section "6. ADMINCOUNT=1 USERS (stale privileged?)"
$adminc = Q -Filter "(&(objectCategory=user)(adminCount=1))" -Props @("sAMAccountName","memberOf","userAccountControl","lastLogonTimestamp","pwdLastSet") -Where "AdminCount"
foreach ($u in $adminc) {
    $sam = (P $u "sAMAccountName")
    $uac = [int64](P $u "userAccountControl" 0)
    $ll  = FileTimeToString (P $u "lastLogonTimestamp" 0)
    $pls = FileTimeToString (P $u "pwdLastSet" 0)
    W "  $sam | UAC:$(DecodeUAC $uac) | LastLogon:$ll | PwdSet:$pls"
}
W "Total: $($adminc.Count)"

# ------------------------------------------------------------
# 7. Kerberoastable (user objects with SPN, exclude krbtgt and disabled)
# ------------------------------------------------------------
Section "7. KERBEROASTABLE USERS (SPN set, not disabled, not krbtgt)"
$kerb = Q -Filter "(&(objectCategory=user)(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Props @("sAMAccountName","servicePrincipalName","memberOf","pwdLastSet","userAccountControl","description") -Where "Kerberoast"
foreach ($u in $kerb) {
    $sam = (P $u "sAMAccountName")
    $spn = PJ $u "servicePrincipalName"
    $pls = FileTimeToString (P $u "pwdLastSet" 0)
    $mof = PJ $u "memberOf"
    $uac = [int64](P $u "userAccountControl" 0)
    $desc= (P $u "description")
    W "  $sam | SPN: $spn | PwdSet: $pls | UAC: $(DecodeUAC $uac) | Desc: $desc"
    W "    MemberOf: $mof"
}
W "Total: $($kerb.Count)"

# ------------------------------------------------------------
# 8. AS-REP roastable (DONT_REQ_PREAUTH)
# ------------------------------------------------------------
Section "8. AS-REP ROASTABLE USERS (UAC bit 0x400000)"
$asrep = Q -Filter "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" `
         -Props @("sAMAccountName","memberOf","pwdLastSet","userAccountControl") -Where "ASREP"
foreach ($u in $asrep) {
    W ("  " + (P $u "sAMAccountName") + " | PwdSet: " + (FileTimeToString (P $u "pwdLastSet" 0)) + " | MemberOf: " + (PJ $u "memberOf"))
}
W "Total: $($asrep.Count)"

# ------------------------------------------------------------
# 9. Risky UAC flags
# ------------------------------------------------------------
Section "9. RISKY UAC FLAGS"
$risky = @(
    @{n="PASSWD_NOTREQD";       f="(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"},
    @{n="DONT_EXPIRE_PASSWD";   f="(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"},
    @{n="ENC_TXT_PWD_OK";       f="(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))"},
    @{n="USE_DES_KEY_ONLY";     f="(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))"},
    @{n="PASSWORD_EXPIRED";     f="(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=8388608))"}
)
foreach ($r in $risky) {
    W "`n--- $($r.n) ---"
    $rs = Q -Filter $r.f -Props @("sAMAccountName","userAccountControl","pwdLastSet") -Where "UAC:$($r.n)"
    foreach ($u in $rs) { W ("  " + (P $u "sAMAccountName")) }
    W "Total: $($rs.Count)"
}

# ------------------------------------------------------------
# 10. Delegation: unconstrained / constrained / RBCD
# ------------------------------------------------------------
Section "10a. UNCONSTRAINED DELEGATION (UAC TRUSTED_FOR_DELEGATION)"
$un = Q -Filter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" `
      -Props @("dNSHostName","sAMAccountName","operatingSystem") -Where "Unconstrained"
foreach ($c in $un) { W ("  " + (P $c "dNSHostName") + " | " + (P $c "sAMAccountName") + " | " + (P $c "operatingSystem")) }
W "Total: $($un.Count)"
W "  NOTE: Filter common DCs; non-DC unconstrained = high-value coercion target"

Section "10b. CONSTRAINED DELEGATION (msDS-AllowedToDelegateTo)"
$cn = Q -Filter "(msDS-AllowedToDelegateTo=*)" `
      -Props @("dNSHostName","sAMAccountName","msds-allowedtodelegateto","userAccountControl") -Where "ConstrainedDeleg"
foreach ($c in $cn) {
    $auth = ""
    $uac = [int64](P $c "userAccountControl" 0)
    if ($uac -band 0x1000000) { $auth = "[Protocol Transition]" } else { $auth = "[Kerberos only]" }
    W ("  " + (P $c "sAMAccountName") + " $auth -> " + (PJ $c "msds-allowedtodelegateto"))
}
W "Total: $($cn.Count)"

Section "10c. RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity set)"
$rb = Q -Filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
      -Props @("dNSHostName","sAMAccountName") -Where "RBCD"
foreach ($c in $rb) { W ("  " + (P $c "dNSHostName") + " | " + (P $c "sAMAccountName")) }
W "Total: $($rb.Count)"

# ------------------------------------------------------------
# 11. gMSA accounts
# ------------------------------------------------------------
Section "11. gMSA ACCOUNTS (msDS-GroupManagedServiceAccount)"
$gmsa = Q -Filter "(objectClass=msDS-GroupManagedServiceAccount)" `
        -Props @("sAMAccountName","servicePrincipalName","msDS-GroupMSAMembership","msDS-ManagedPasswordInterval","memberOf") -Where "gMSA"
foreach ($g in $gmsa) {
    W ("`ngMSA: " + (P $g "sAMAccountName"))
    W ("  SPN: " + (PJ $g "servicePrincipalName"))
    W ("  MemberOf: " + (PJ $g "memberOf"))
    W ("  ManagedPwdInterval: " + (P $g "msDS-ManagedPasswordInterval"))
    W "  --> If you can read msDS-ManagedPassword (i.e., you're in msDS-GroupMSAMembership), you own this account"
}
W "Total: $($gmsa.Count)"

# ------------------------------------------------------------
# 12. MachineAccountQuota
# ------------------------------------------------------------
Section "12. MACHINE ACCOUNT QUOTA"
$root = Q -Filter "(objectClass=domain)" -Props @("ms-DS-MachineAccountQuota") -SearchBase $baseDN -Where "MAQ"
if ($root.Count -gt 0) {
    $maq = (P $root[0] "ms-DS-MachineAccountQuota" "?")
    W "ms-DS-MachineAccountQuota = $maq  (if > 0, RBCD attacks possible by any user)"
}

# ------------------------------------------------------------
# 13. All computers (with OS, lastLogon)  — tag old OS
# ------------------------------------------------------------
Section "13. ALL COMPUTERS (OS, last logon)"
$comps = Q -Filter "(objectCategory=computer)" `
         -Props @("dNSHostName","sAMAccountName","operatingSystem","operatingSystemVersion","operatingSystemServicePack","lastLogonTimestamp","userAccountControl") -Where "Computers"
W "Total computer objects: $($comps.Count)"
$old = @()
foreach ($c in $comps) {
    $os  = (P $c "operatingSystem")
    $ver = (P $c "operatingSystemVersion")
    $sp  = (P $c "operatingSystemServicePack")
    $ll  = FileTimeToString (P $c "lastLogonTimestamp" 0)
    W ("  " + (P $c "dNSHostName") + " | " + $os + " " + $ver + " " + $sp + " | LastLogon: $ll")
    if ($os -match "2003|2008|XP|Vista|Windows 7|Windows 8(?!\.)|2012") { $old += (P $c "dNSHostName") }
}
W "`n--- Computers running old/EOL OS ---"
$old | ForEach-Object { W "  $_" }

# ------------------------------------------------------------
# 14. LAPS (legacy ms-Mcs-AdmPwd + new msLAPS-Password) readable check
# ------------------------------------------------------------
Section "14. LAPS — legacy ms-Mcs-AdmPwd readable?"
$laps1 = Q -Filter "(ms-Mcs-AdmPwd=*)" -Props @("dNSHostName","sAMAccountName","ms-Mcs-AdmPwd","ms-Mcs-AdmPwdExpirationTime") -Where "LAPSlegacy"
foreach ($l in $laps1) {
    W ("  " + (P $l "dNSHostName") + " | pwd: " + (P $l "ms-Mcs-AdmPwd") + " | exp: " + (FileTimeToString (P $l "ms-Mcs-AdmPwdExpirationTime" 0)))
}
W "Total readable: $($laps1.Count)"
Section "14b. LAPS — new msLAPS-Password readable?"
$laps2 = Q -Filter "(msLAPS-Password=*)" -Props @("dNSHostName","sAMAccountName","msLAPS-Password","msLAPS-PasswordExpirationTime") -Where "LAPSnew"
foreach ($l in $laps2) {
    W ("  " + (P $l "dNSHostName") + " | encpwd: " + (P $l "msLAPS-Password") + " | exp: " + (FileTimeToString (P $l "msLAPS-PasswordExpirationTime" 0)))
}
W "Total readable (new attr): $($laps2.Count)"

# ------------------------------------------------------------
# 15. Service computers by SPN (SQL, HTTP, Exchange, Veeam)
# ------------------------------------------------------------
Section "15. SERVICE-BEARING COMPUTERS BY SPN"
$svc = Q -Filter "(&(objectCategory=computer)(servicePrincipalName=*))" -Props @("dNSHostName","servicePrincipalName") -Where "ServiceComputers"
$sql = @(); $http = @(); $exch = @(); $veeam = @(); $rdp = @(); $other = @()
foreach ($s in $svc) {
    $h = (P $s "dNSHostName"); $spns = PJ $s "servicePrincipalName"
    if ($spns -match "MSSQL|SQLServer")   { $sql   += "$h | $spns" }
    if ($spns -match "HTTP/|HTTPS/")      { $http  += "$h | $spns" }
    if ($spns -match "exchangeMDB|SMTP|exchangeRFR|exchangeAB") { $exch += "$h | $spns" }
    if ($spns -match "Veeam|VeeamBackup") { $veeam += "$h | $spns" }
    if ($spns -match "TERMSRV")           { $rdp   += "$h | $spns" }
}
W "`n--- SQL servers ---";       $sql   | ForEach-Object { W "  $_" }
W "`n--- HTTP/HTTPS hosts ---";  $http  | ForEach-Object { W "  $_" }
W "`n--- Exchange ---";          $exch  | ForEach-Object { W "  $_" }
W "`n--- Veeam ---";             $veeam | ForEach-Object { W "  $_" }
W "`n--- RDP advertised ---";    $rdp   | ForEach-Object { W "  $_" }

# ------------------------------------------------------------
# 16. AD CS — CAs and Templates with ESC1/ESC2/ESC3/ESC4 hints
# ------------------------------------------------------------
Section "16a. AD CS — Certificate Authorities"
$cas = Q -Filter "(objectClass=pKIEnrollmentService)" -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN" `
       -Props @("cn","dNSHostName","certificateTemplates") -Where "CAs"
if ($cas.Count -eq 0) { W "No enterprise CAs found in this forest" }
foreach ($c in $cas) {
    W ("CA: " + (P $c "cn") + " | Host: " + (P $c "dNSHostName"))
    W ("  Published templates: " + (PJ $c "certificateTemplates" ", "))
}

Section "16b. AD CS — Certificate Templates (ESC heuristics)"
$tmpls = Q -Filter "(objectClass=pKICertificateTemplate)" -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN" `
         -Props @("cn","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag","pKIExtendedKeyUsage","msPKI-RA-Signature","msPKI-Certificate-Application-Policy","nTSecurityDescriptor") -Where "Templates"
foreach ($t in $tmpls) {
    $name = (P $t "cn")
    $nflag = [int64](P $t "msPKI-Certificate-Name-Flag" 0)
    $eflag = [int64](P $t "msPKI-Enrollment-Flag" 0)
    $rasig = [int](P $t "msPKI-RA-Signature" 0)
    $eku   = PJ $t "pKIExtendedKeyUsage" ", "
    $tags = @()
    if ($nflag -band 0x00000001) { $tags += "ENROLLEE_SUPPLIES_SUBJECT" }
    if (($eflag -band 0x00000002) -eq 0) { $tags += "NO_MANAGER_APPROVAL" }
    if ($rasig -eq 0) { $tags += "NO_RA_SIG" }
    $clientAuth = ($eku -match "1.3.6.1.5.5.7.3.2|1.3.6.1.5.2.3.4|2.5.29.37.0|1.3.6.1.4.1.311.20.2.2")
    $anyPurpose = ($eku -match "2.5.29.37.0")

    $esc = @()
    if (($tags -contains "ENROLLEE_SUPPLIES_SUBJECT") -and ($tags -contains "NO_MANAGER_APPROVAL") -and ($tags -contains "NO_RA_SIG") -and $clientAuth) { $esc += "ESC1?" }
    if ($anyPurpose -and ($tags -contains "NO_MANAGER_APPROVAL") -and ($tags -contains "NO_RA_SIG"))       { $esc += "ESC2?" }
    if ($eku -match "1.3.6.1.4.1.311.20.2.1")                                                                   { $esc += "ESC3?(EnrollmentAgent)" }
    W ("  Template: $name | EKU: $eku | Tags: $($tags -join ',') | Suspect: $($esc -join ',')")
}
W "`nNote: ESC4/5/6/7 require ACL parsing on each template/CA; not done here. Use certipy from Linux for full coverage."
W "Note: ESC8 (Web Enrollment NTLM relay) requires checking IIS/HTTP CES endpoints on each CA host."

# ------------------------------------------------------------
# 17. OUs (structure)
# ------------------------------------------------------------
Section "17. ORGANIZATIONAL UNITS"
$ous = Q -Filter "(objectCategory=organizationalUnit)" -Props @("ou","distinguishedName","gPLink") -Where "OUs"
foreach ($o in $ous) { W ("  " + (P $o "distinguishedName")) }
W "Total OUs: $($ous.Count)"

# ------------------------------------------------------------
# 18. ACL probe on Tier-0 (who has WriteDACL/WriteOwner/GenericAll)
# ------------------------------------------------------------
Section "18. ACL PROBE — Tier-0 objects"
$tier0Names = @("krbtgt","Administrator","svc_srv_backup")
$tier0Names += @("Domain Admins","Enterprise Admins","Schema Admins","AdminSDHolder")
$dangerous  = @("GenericAll","GenericWrite","WriteDACL","WriteOwner","WriteProperty","Self","ForceChangePassword","AllExtendedRights")

function ProbeAcl {
    param([string]$objDN, [string]$tag)
    try {
        $de = [ADSI]"LDAP://$objDN"
        $sd = $de.psbase.ObjectSecurity
        if ($null -eq $sd) { W "  $tag : (no SD)"; return }
        foreach ($ace in $sd.Access) {
            $rights = $ace.ActiveDirectoryRights.ToString()
            $hit = $false
            foreach ($d in $dangerous) { if ($rights -match $d) { $hit = $true; break } }
            if ($hit -and $ace.AccessControlType -eq "Allow") {
                W "  [$tag] $($ace.IdentityReference) -> $rights (inherited=$($ace.IsInherited))"
            }
        }
    } catch { LogErr "ACL:$tag" $_ }
}

foreach ($n in $tier0Names) {
    $r = Q -Filter "(|(sAMAccountName=$n)(cn=$n))" -Props @("distinguishedName") -Where "ACLfind:$n"
    foreach ($x in $r) { ProbeAcl (P $x "distinguishedName") $n }
}
W "(AdminSDHolder ACL governs all protected accounts)"
$adminSDH = Q -Filter "(cn=AdminSDHolder)" -SearchBase "CN=System,$baseDN" -Props @("distinguishedName") -Where "AdminSDHolder"
foreach ($x in $adminSDH) { ProbeAcl (P $x "distinguishedName") "AdminSDHolder" }

# ------------------------------------------------------------
# 19. Domain root ACL (who can DCSync? Replicating Directory Changes / All)
# ------------------------------------------------------------
Section "19. DOMAIN ROOT ACL — DCSync rights (Repl-Dir-Changes-All)"
try {
    $de = [ADSI]"LDAP://$baseDN"
    $sd = $de.psbase.ObjectSecurity
    foreach ($ace in $sd.Access) {
        $oid = ""
        try { $oid = $ace.ObjectType.ToString() } catch {}
        if ($oid -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or
            $oid -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or
            $oid -eq "89e95b76-444d-4c62-991a-0facbeda640c") {
            W ("  " + $ace.IdentityReference + " -> " + $ace.ActiveDirectoryRights + " (object=" + $oid + ")")
        }
    }
} catch { LogErr "DomainRootACL" $_ }
W "(Above ACEs grant DCSync: any principal listed can extract krbtgt/all hashes)"

# ------------------------------------------------------------
# 20. SYSVOL — GPP / scripts hunt for credentials
# ------------------------------------------------------------
Section "20. SYSVOL & NETLOGON HUNT (cpassword, scripts)"
$sysvolPath = "\\$($env:USERDNSDOMAIN)\SYSVOL\$($env:USERDNSDOMAIN)"
$netlogon   = "\\$($env:USERDNSDOMAIN)\NETLOGON"
W "SYSVOL path: $sysvolPath"
try {
    $cpFiles = Get-ChildItem -Path $sysvolPath -Recurse -Include *.xml,*.ini,*.bat,*.ps1,*.vbs,*.cmd -ErrorAction SilentlyContinue
    W "Scanning $($cpFiles.Count) files for cpassword / sensitive patterns..."
    foreach ($f in $cpFiles) {
        try {
            $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match 'cpassword="[^"]+"' -or $content -match 'cpassword=''[^'']+''') {
                W "  [GPP] $($f.FullName)"
                foreach ($m in [regex]::Matches($content, 'cpassword="([^"]+)"')) { W "    cpassword: $($m.Groups[1].Value)" }
            }
            if ($content -match '(?i)(password|pwd|passwd|secret)\s*[:=]\s*[^\r\n;\s]{4,}') {
                $sn = [regex]::Matches($content, '(?i)(password|pwd|passwd|secret)\s*[:=]\s*[^\r\n;\s]{4,}')
                foreach ($m in $sn) { W "  [STR] $($f.FullName) :: $($m.Value)" }
            }
        } catch { }
    }
} catch { LogErr "SYSVOLscan" $_ }
W "`nNETLOGON listing:"
try { Get-ChildItem -Path $netlogon -ErrorAction SilentlyContinue | ForEach-Object { W ("  " + $_.FullName) } } catch { LogErr "Netlogon" $_ }

# ------------------------------------------------------------
# 21. Stale users (no logon > 180d, password unchanged > 365d)
# ------------------------------------------------------------
Section "21. STALE ENABLED USERS (>180d no logon OR pwd >365d)"
$cutLogon = (Get-Date).AddDays(-180).ToFileTime()
$cutPwd   = (Get-Date).AddDays(-365).ToFileTime()
$stale = Q -Filter "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(lastLogonTimestamp<=$cutLogon)(pwdLastSet<=$cutPwd)))" `
        -Props @("sAMAccountName","lastLogonTimestamp","pwdLastSet","userAccountControl","memberOf") -Where "Stale"
foreach ($u in $stale) {
    W ("  " + (P $u "sAMAccountName") + " | LastLogon: " + (FileTimeToString (P $u "lastLogonTimestamp" 0)) + " | PwdSet: " + (FileTimeToString (P $u "pwdLastSet" 0)))
}
W "Total: $($stale.Count)"

# ------------------------------------------------------------
# 22. Shares accessible from this host (SYSVOL/NETLOGON + admin shares)
# ------------------------------------------------------------
Section "22. SMB SHARE ACCESS PROBE on a few interesting hosts"
$probe = @($env:USERDNSDOMAIN, "ADSYNC1", "ADSYNC3", "AD-SYNC1", "ADSYNC-IL", "ADSYNC-STAFFING")
foreach ($p in $probe) {
    W "`n--- $p ---"
    try { net view \\$p 2>&1 | Out-File $out -Append } catch { LogErr "NetView:$p" $_ }
    foreach ($s in @("C$","ADMIN$","IPC$","backup","Backup","Scripts","NETLOGON","SYSVOL")) {
        try {
            $null = Get-ChildItem "\\$p\$s" -ErrorAction Stop | Select-Object -First 1
            W "  [READ-OK] \\$p\$s"
        } catch {
            # silent miss
        }
    }
}

# ------------------------------------------------------------
# Done
# ------------------------------------------------------------
Section "DONE"
W "Output saved to $out"
W "Errors (if any) logged to $err"
W "Send both files back for analysis."
