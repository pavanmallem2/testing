# ============================================================
# AD Attack Path Enumeration - Enhanced v2 - IIPL.COM
# Native PowerShell/.NET only - AMSI safe
# Output: ad_enum_v2.txt in current directory
# ============================================================

$outputFile = ".\ad_enum_v2.txt"
$domain = "IIPL.COM"
$ldapBase = "DC=IIPL,DC=COM"

"=" * 70 | Out-File $outputFile
"AD ATTACK PATH ENUMERATION - $domain" | Out-File $outputFile -Append
"Date: $(Get-Date)" | Out-File $outputFile -Append
"User: $env:USERDOMAIN\$env:USERNAME" | Out-File $outputFile -Append
"=" * 70 | Out-File $outputFile -Append

# LDAP Connectivity Test
Write-Host "[*] Testing LDAP connectivity..." -ForegroundColor Yellow
try {
    $testSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
    $testSearcher.Filter = "(objectClass=domain)"
    $testResult = $testSearcher.FindOne()
    if ($testResult) {
        Write-Host "[+] LDAP OK: $($testResult.Properties['distinguishedname'][0])" -ForegroundColor Green
        "LDAP Test: OK - $($testResult.Properties['distinguishedname'][0])" | Out-File $outputFile -Append
    }
} catch {
    Write-Host "[-] LDAP FAILED: $($_.Exception.Message)" -ForegroundColor Red
    "LDAP Test: FAILED - $($_.Exception.Message)" | Out-File $outputFile -Append
    Write-Host "[-] Script will continue but LDAP queries will fail" -ForegroundColor Red
}

function Run-LDAPQuery {
    param([string]$Filter, [string[]]$Properties, [string]$SearchBase = "")
    try {
        $s = New-Object DirectoryServices.DirectorySearcher
        if ($SearchBase -ne "" -and $SearchBase -ne $ldapBase) {
            $s.SearchRoot = [ADSI]"LDAP://$SearchBase"
        } else {
            $s.SearchRoot = [ADSI]""
        }
        $s.Filter = $Filter
        $s.PageSize = 1000
        if ($Properties) { $s.PropertiesToLoad.AddRange($Properties) }
        return $s.FindAll()
    } catch { return $null }
}

function Write-Section {
    param([string]$Title)
    "`n" + "=" * 70 | Out-File $outputFile -Append
    "  $Title" | Out-File $outputFile -Append
    "=" * 70 | Out-File $outputFile -Append
    Write-Host "[*] $Title" -ForegroundColor Cyan
}

# ============================================================
# 1. CURRENT USER CONTEXT
# ============================================================
Write-Section "1. CURRENT USER CONTEXT"
whoami /all 2>&1 | Out-File $outputFile -Append
"Logon Server: $env:LOGONSERVER" | Out-File $outputFile -Append
"Language Mode: $($ExecutionContext.SessionState.LanguageMode)" | Out-File $outputFile -Append

# Local admin check
$isLocalAdmin = (whoami /groups 2>$null) -match "S-1-5-32-544"
"Local Admin: $isLocalAdmin" | Out-File $outputFile -Append

# ============================================================
# 2. DOMAIN INFO & DOMAIN CONTROLLERS
# ============================================================
Write-Section "2. DOMAIN INFORMATION"
try {
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    "Domain: $($domainObj.Name)" | Out-File $outputFile -Append
    "Forest: $($domainObj.Forest)" | Out-File $outputFile -Append
    foreach ($dc in $domainObj.DomainControllers) {
        "  DC: $($dc.Name) | IP: $($dc.IPAddress) | OS: $($dc.OSVersion)" | Out-File $outputFile -Append
    }
} catch { "Error: $($_.Exception.Message)" | Out-File $outputFile -Append }

# ============================================================
# 3. PASSWORD POLICY
# ============================================================
Write-Section "3. PASSWORD POLICY"
net accounts /domain 2>&1 | Out-File $outputFile -Append

# Fine-grained password policies
$fgpp = Run-LDAPQuery -Filter "(objectClass=msDS-PasswordSettings)" -Properties @("cn","msds-lockoutthreshold","msds-minimumpasswordlength","msds-psoappliesto")
if ($fgpp -and $fgpp.Count -gt 0) {
    "`nFine-Grained Password Policies:" | Out-File $outputFile -Append
    foreach ($f in $fgpp) {
        $p = $f.Properties
        "  Policy: $($p['cn'][0]) | MinLength: $($p['msds-minimumpasswordlength'][0]) | Lockout: $($p['msds-lockoutthreshold'][0])" | Out-File $outputFile -Append
        "  Applies To: $($p['msds-psoappliesto'] -join '; ')" | Out-File $outputFile -Append
    }
} else {
    "No fine-grained password policies found" | Out-File $outputFile -Append
}

# ============================================================
# 4. DOMAIN TRUSTS
# ============================================================
Write-Section "4. DOMAIN TRUSTS"
$trusts = Run-LDAPQuery -Filter "(objectClass=trustedDomain)" -Properties @("cn","trustdirection","trusttype","trustattributes")
if ($trusts -and $trusts.Count -gt 0) {
    foreach ($t in $trusts) {
        $p = $t.Properties
        $dir = switch([int]$p["trustdirection"][0]) { 1 {"Inbound"} 2 {"Outbound"} 3 {"Bidirectional"} default {"Unknown"} }
        "Trust: $($p['cn'][0]) | Direction: $dir | Type: $($p['trusttype'][0])" | Out-File $outputFile -Append
    }
} else { "No trusts found" | Out-File $outputFile -Append }

# ============================================================
# 5. PRIVILEGED GROUPS & MEMBERS
# ============================================================
Write-Section "5. PRIVILEGED GROUPS"
$privGroups = @(
    "Domain Admins","Enterprise Admins","Schema Admins","Administrators",
    "Account Operators","Server Operators","Backup Operators","Print Operators",
    "DnsAdmins","Remote Desktop Users","Group Policy Creator Owners",
    "Remote Management Users","Hyper-V Administrators","Event Log Readers"
)
foreach ($g in $privGroups) {
    "`n--- $g ---" | Out-File $outputFile -Append
    net group "$g" /domain 2>&1 | Out-File $outputFile -Append
}

# Also check local groups on current machine
"`n--- Local Administrators (this machine) ---" | Out-File $outputFile -Append
net localgroup administrators 2>&1 | Out-File $outputFile -Append

# ============================================================
# 6. ALL USERS - FULL DETAILS
# ============================================================
Write-Section "6. ALL DOMAIN USERS"
$users = Run-LDAPQuery -Filter "(&(objectCategory=person)(objectClass=user))" -Properties @(
    "samaccountname","description","memberof","pwdlastset","lastlogon",
    "useraccountcontrol","admincount","serviceprincipalname","mail",
    "distinguishedname","whencreated","scriptpath","homedirectory",
    "profilepath","logoncount"
)

$enabledCount = 0; $disabledCount = 0
$adminUsers = @(); $spnUsers = @(); $descUsers = @()
$neverExpire = @(); $staleUsers = @(); $asrepUsers = @()
$neverLogon = @(); $homeDirs = @(); $logonScripts = @()

if ($users) {
    foreach ($u in $users) {
        $p = $u.Properties
        $name = "$($p['samaccountname'][0])"
        $uac = [int]$p["useraccountcontrol"][0]
        $disabled = ($uac -band 2) -ne 0
        $dontExpire = ($uac -band 65536) -ne 0
        $noPreAuth = ($uac -band 4194304) -ne 0
        $trustedDeleg = ($uac -band 524288) -ne 0
        $constrainedDeleg = ($uac -band 16777216) -ne 0
        $desc = if($p["description"].Count -gt 0){"$($p['description'][0])"}else{""}
        $spn = if($p["serviceprincipalname"].Count -gt 0){$p["serviceprincipalname"] -join "; "}else{""}
        $adminCount = if($p["admincount"].Count -gt 0){"$($p['admincount'][0])"}else{"0"}
        $memberOf = if($p["memberof"].Count -gt 0){$p["memberof"] -join "; "}else{""}
        $script = if($p["scriptpath"].Count -gt 0){"$($p['scriptpath'][0])"}else{""}
        $homeDir = if($p["homedirectory"].Count -gt 0){"$($p['homedirectory'][0])"}else{""}
        $logonCount = if($p["logoncount"].Count -gt 0){"$($p['logoncount'][0])"}else{"0"}

        $pwdSet = "Never"
        if ($p["pwdlastset"].Count -gt 0 -and $p["pwdlastset"][0] -ne 0) {
            try { $pwdSet = [datetime]::FromFileTime($p["pwdlastset"][0]).ToString("yyyy-MM-dd") } catch {}
        }
        $lastLogon = "Never"
        if ($p["lastlogon"].Count -gt 0 -and $p["lastlogon"][0] -ne 0) {
            try { $lastLogon = [datetime]::FromFileTime($p["lastlogon"][0]).ToString("yyyy-MM-dd") } catch {}
        }

        $status = if($disabled){"DISABLED"}else{"ENABLED"}
        $flags = @()
        if ($dontExpire) { $flags += "PwdNeverExpires" }
        if ($noPreAuth) { $flags += "NoPreAuth" }
        if ($trustedDeleg) { $flags += "TrustedForDelegation" }
        if ($constrainedDeleg) { $flags += "ConstrainedDelegation" }
        if ($adminCount -eq "1") { $flags += "AdminCount" }
        $flagStr = if($flags.Count -gt 0){$flags -join ","}else{"None"}

        if (-not $disabled) { $enabledCount++ } else { $disabledCount++ }

        if ($adminCount -eq "1") { $adminUsers += $name }
        if ($spn -ne "" -and -not $disabled) { $spnUsers += "$name | SPN: $spn | Groups: $memberOf" }
        if ($desc -ne "") { $descUsers += "$name | $desc" }
        if ($dontExpire -and -not $disabled) { $neverExpire += $name }
        if ($noPreAuth -and -not $disabled) { $asrepUsers += $name }
        if ($script -ne "") { $logonScripts += "$name | $script" }
        if ($homeDir -ne "") { $homeDirs += "$name | $homeDir" }

        if ($lastLogon -ne "Never" -and -not $disabled) {
            try {
                $d = [datetime]::ParseExact($lastLogon,"yyyy-MM-dd",$null)
                if ($d -lt (Get-Date).AddDays(-90)) { $staleUsers += "$name | Last: $lastLogon" }
            } catch {}
        }
        if ($lastLogon -eq "Never" -and -not $disabled -and $logonCount -eq "0") {
            $neverLogon += $name
        }

        "$name | $status | PwdSet: $pwdSet | LastLogon: $lastLogon | Flags: $flagStr | Desc: $desc" | Out-File $outputFile -Append
    }
    "`nTotal: $($users.Count) | Enabled: $enabledCount | Disabled: $disabledCount" | Out-File $outputFile -Append
    Write-Host "  Found $($users.Count) users ($enabledCount enabled)" -ForegroundColor Green
}

# ============================================================
# 7. ADMIN FLAGGED ACCOUNTS
# ============================================================
Write-Section "7. ADMIN FLAGGED ACCOUNTS (adminCount=1)"
foreach ($a in $adminUsers) { $a | Out-File $outputFile -Append }
"Total: $($adminUsers.Count)" | Out-File $outputFile -Append

# ============================================================
# 8. KERBEROASTABLE ACCOUNTS
# ============================================================
Write-Section "8. KERBEROASTABLE ACCOUNTS"
foreach ($s in $spnUsers) { $s | Out-File $outputFile -Append }
"Total: $($spnUsers.Count)" | Out-File $outputFile -Append

# ============================================================
# 9. AS-REP ROASTABLE
# ============================================================
Write-Section "9. AS-REP ROASTABLE ACCOUNTS"
if ($asrepUsers.Count -gt 0) {
    foreach ($a in $asrepUsers) { $a | Out-File $outputFile -Append }
} else { "None found" | Out-File $outputFile -Append }

# ============================================================
# 10. USER DESCRIPTIONS
# ============================================================
Write-Section "10. USER DESCRIPTIONS (check for credentials)"
foreach ($d in $descUsers) { $d | Out-File $outputFile -Append }

# ============================================================
# 11. PASSWORD NEVER EXPIRES
# ============================================================
Write-Section "11. PASSWORD NEVER EXPIRES (Enabled)"
foreach ($n in $neverExpire) { $n | Out-File $outputFile -Append }
"Total: $($neverExpire.Count)" | Out-File $outputFile -Append

# ============================================================
# 12. STALE ACCOUNTS
# ============================================================
Write-Section "12. STALE ACCOUNTS (90+ days)"
foreach ($s in $staleUsers) { $s | Out-File $outputFile -Append }
"Total: $($staleUsers.Count)" | Out-File $outputFile -Append

# ============================================================
# 13. NEVER LOGGED ON ACCOUNTS
# ============================================================
Write-Section "13. NEVER LOGGED ON (Enabled)"
foreach ($n in $neverLogon) { $n | Out-File $outputFile -Append }
"Total: $($neverLogon.Count)" | Out-File $outputFile -Append

# ============================================================
# 14. LOGON SCRIPTS (may contain credentials)
# ============================================================
Write-Section "14. LOGON SCRIPTS ASSIGNED"
foreach ($l in $logonScripts) { $l | Out-File $outputFile -Append }
"Total: $($logonScripts.Count)" | Out-File $outputFile -Append

# ============================================================
# 15. HOME DIRECTORIES
# ============================================================
Write-Section "15. HOME DIRECTORIES"
foreach ($h in $homeDirs) { $h | Out-File $outputFile -Append }
"Total: $($homeDirs.Count)" | Out-File $outputFile -Append

# ============================================================
# 16. ALL COMPUTERS
# ============================================================
Write-Section "16. DOMAIN COMPUTERS"
$computers = Run-LDAPQuery -Filter "(objectCategory=computer)" -Properties @(
    "cn","operatingsystem","operatingsystemversion","dnshostname",
    "useraccountcontrol","lastlogon","ms-mcs-admpwd","operatingsystemservicepack",
    "whencreated"
)

$oldOS = @(); $lapsFound = @(); $allComputers = @()

if ($computers) {
    foreach ($c in $computers) {
        $p = $c.Properties
        $name = "$($p['cn'][0])"
        $os = if($p["operatingsystem"].Count -gt 0){"$($p['operatingsystem'][0])"}else{"Unknown"}
        $dns = if($p["dnshostname"].Count -gt 0){"$($p['dnshostname'][0])"}else{""}
        $sp = if($p["operatingsystemservicepack"].Count -gt 0){"$($p['operatingsystemservicepack'][0])"}else{""}

        "$name | $os $sp | $dns" | Out-File $outputFile -Append
        $allComputers += $dns

        if ($os -match "2008|2003|Windows 7|Windows XP|Vista|2000") {
            $oldOS += "$name | $os $sp | $dns"
        }
        if ($p["ms-mcs-admpwd"].Count -gt 0) {
            $lapsFound += "$name : $($p['ms-mcs-admpwd'][0])"
        }
    }
    "`nTotal: $($computers.Count)" | Out-File $outputFile -Append
    Write-Host "  Found $($computers.Count) computers" -ForegroundColor Green
}

# ============================================================
# 17. OLD / VULNERABLE OS
# ============================================================
Write-Section "17. OLD / VULNERABLE OS"
if ($oldOS.Count -gt 0) {
    foreach ($o in $oldOS) { $o | Out-File $outputFile -Append }
    Write-Host "  Found $($oldOS.Count) old OS machines!" -ForegroundColor Red
} else { "None found" | Out-File $outputFile -Append }

# ============================================================
# 18. LAPS PASSWORDS
# ============================================================
Write-Section "18. LAPS PASSWORDS"
if ($lapsFound.Count -gt 0) {
    foreach ($l in $lapsFound) { $l | Out-File $outputFile -Append }
    Write-Host "  LAPS PASSWORDS FOUND!" -ForegroundColor Red
} else { "Not readable or not deployed" | Out-File $outputFile -Append }

# ============================================================
# 19. UNCONSTRAINED DELEGATION
# ============================================================
Write-Section "19. UNCONSTRAINED DELEGATION"
$unconstrained = Run-LDAPQuery -Filter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -Properties @("cn","dnshostname","operatingsystem")
if ($unconstrained) {
    foreach ($u in $unconstrained) {
        $p = $u.Properties
        "$($p['cn'][0]) | $($p['operatingsystem'][0]) | $($p['dnshostname'][0])" | Out-File $outputFile -Append
    }
    "Total: $($unconstrained.Count)" | Out-File $outputFile -Append
}

# ============================================================
# 20. CONSTRAINED DELEGATION
# ============================================================
Write-Section "20. CONSTRAINED DELEGATION"
$constrained = Run-LDAPQuery -Filter "(&(objectCategory=*)(msds-allowedtodelegateto=*))" -Properties @("cn","samaccountname","msds-allowedtodelegateto","objectcategory")
if ($constrained) {
    foreach ($c in $constrained) {
        $p = $c.Properties
        "ACCOUNT: $($p['samaccountname'][0])" | Out-File $outputFile -Append
        "DELEGATES TO: $($p['msds-allowedtodelegateto'] -join '; ')" | Out-File $outputFile -Append
        "---" | Out-File $outputFile -Append
    }
}

# ============================================================
# 21. RESOURCE-BASED CONSTRAINED DELEGATION
# ============================================================
Write-Section "21. RBCD"
$rbcd = Run-LDAPQuery -Filter "(&(objectCategory=computer)(msds-allowedtoactonbehalfofotheridentity=*))" -Properties @("cn","samaccountname")
if ($rbcd -and $rbcd.Count -gt 0) {
    foreach ($r in $rbcd) { "$($r.Properties['cn'][0])" | Out-File $outputFile -Append }
} else { "None found" | Out-File $outputFile -Append }

# ============================================================
# 22. MANAGED SERVICE ACCOUNTS (gMSA)
# ============================================================
Write-Section "22. GROUP MANAGED SERVICE ACCOUNTS (gMSA)"
$gmsa = Run-LDAPQuery -Filter "(objectClass=msDS-GroupManagedServiceAccount)" -Properties @("samaccountname","msds-groupmsamembership","msds-managedpasswordinterval","serviceprincipalname","memberof")
if ($gmsa -and $gmsa.Count -gt 0) {
    foreach ($g in $gmsa) {
        $p = $g.Properties
        "gMSA: $($p['samaccountname'][0])" | Out-File $outputFile -Append
        $spnVal = if($p["serviceprincipalname"].Count -gt 0){$p["serviceprincipalname"] -join "; "}else{"None"}
        "  SPN: $spnVal" | Out-File $outputFile -Append
        $moVal = if($p["memberof"].Count -gt 0){$p["memberof"] -join "; "}else{"None"}
        "  MemberOf: $moVal" | Out-File $outputFile -Append
    }
} else { "None found" | Out-File $outputFile -Append }

# ============================================================
# 23. GPOs
# ============================================================
Write-Section "23. GROUP POLICY OBJECTS"
$gpos = Run-LDAPQuery -Filter "(objectClass=groupPolicyContainer)" -Properties @("displayname","gpcfilesyspath","cn","flags")
if ($gpos) {
    foreach ($g in $gpos) {
        $p = $g.Properties
        $status = switch([int]$p["flags"][0]) { 0 {"Enabled"} 1 {"User Disabled"} 2 {"Computer Disabled"} 3 {"All Disabled"} default {"Unknown"} }
        "$($p['displayname'][0]) | $status | $($p['gpcfilesyspath'][0])" | Out-File $outputFile -Append
    }
    "`nTotal: $($gpos.Count)" | Out-File $outputFile -Append
}

# ============================================================
# 24. SYSVOL & NETLOGON
# ============================================================
Write-Section "24. SYSVOL & NETLOGON FILES"

"--- NETLOGON ---" | Out-File $outputFile -Append
$netlogon = Get-ChildItem "\\$domain\NETLOGON\" -Recurse -ErrorAction SilentlyContinue
if ($netlogon) {
    foreach ($f in $netlogon) { "$($f.FullName) | $($f.Length)B" | Out-File $outputFile -Append }
}

"--- SYSVOL SCRIPTS/CONFIGS ---" | Out-File $outputFile -Append
$sysvolFiles = Get-ChildItem "\\$domain\SYSVOL" -Recurse -Include *.bat,*.cmd,*.vbs,*.ps1,*.txt,*.ini,*.cfg,*.xml,*.config,*.inf -ErrorAction SilentlyContinue
if ($sysvolFiles) {
    foreach ($f in $sysvolFiles) { "$($f.FullName) | $($f.Length)B" | Out-File $outputFile -Append }
    Write-Host "  Found $($sysvolFiles.Count) files in SYSVOL" -ForegroundColor Green
}

# ============================================================
# 25. CREDENTIAL HUNTING IN SYSVOL
# ============================================================
Write-Section "25. CREDENTIAL HUNTING IN SYSVOL"

$kw = @(("pas"+"sword"),("pas"+"wd"),("cre"+"dential"),("cpas"+"sword"),("net "+"use"),("sec"+"ret"),("user"+"name="),("connec"+"tionstring"))

foreach ($f in $sysvolFiles) {
    try {
        # Skip GPT.INI and the script itself
        if ($f.Name -eq "GPT.INI" -or $f.Name -eq "ad_enum_v2.ps1") { continue }
        $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -and $content.Length -gt 10) {
            foreach ($k in $kw) {
                if ($content -match $k) {
                    "`nMATCH [$k] in: $($f.FullName)" | Out-File $outputFile -Append
                    $content | Out-File $outputFile -Append
                    "---" | Out-File $outputFile -Append
                    Write-Host "  CRED FOUND: $($f.FullName)" -ForegroundColor Red
                    break
                }
            }
        }
    } catch {}
}

# ============================================================
# 26. NETWORK SHARES ON KEY SERVERS
# ============================================================
Write-Section "26. NETWORK SHARES"
$keyServers = @("COMPND2K12DC","COMPND-SRV-003","COMPND-VM-PDC","SOLITAIRE","COMPND-VMSRV-01","COMPND-VMSRV-05","COMPND-VMSRV-02","COMPND-VMSRV-07")

foreach ($srv in $keyServers) {
    "`n--- $srv ---" | Out-File $outputFile -Append
    $shares = net view "\\$srv" 2>&1
    $shares | Out-File $outputFile -Append

    try {
        $null = Get-ChildItem "\\$srv\C$" -ErrorAction Stop | Select-Object -First 1
        "  ** C$ ACCESSIBLE **" | Out-File $outputFile -Append
        Write-Host "  ADMIN SHARE $srv C$ ACCESSIBLE!" -ForegroundColor Red
    } catch {
        "  C$ not accessible" | Out-File $outputFile -Append
    }

    try {
        $null = Get-ChildItem "\\$srv\ADMIN$" -ErrorAction Stop | Select-Object -First 1
        "  ** ADMIN$ ACCESSIBLE **" | Out-File $outputFile -Append
        Write-Host "  ADMIN$ on $srv ACCESSIBLE!" -ForegroundColor Red
    } catch {
        "  ADMIN$ not accessible" | Out-File $outputFile -Append
    }
}

# ============================================================
# 27. ACL CHECKS ON HIGH VALUE TARGETS
# ============================================================
Write-Section "27. ACL CHECKS"

$targets = @("Administrator","svc_srv_backup","gcserver","vmmservice","krbtgt")

foreach ($target in $targets) {
    "`n--- $target ---" | Out-File $outputFile -Append
    try {
        $r = Run-LDAPQuery -Filter "(&(objectCategory=person)(samaccountname=$target))" -Properties @("distinguishedname")
        if ($r -and $r.Count -gt 0) {
            $entry = $r[0].GetDirectoryEntry()
            $acl = $entry.ObjectSecurity
            foreach ($ace in $acl.Access) {
                $id = $ace.IdentityReference.ToString()
                $rights = $ace.ActiveDirectoryRights.ToString()
                # Flag dangerous rights
                if ($id -match "Authenticated Users|Everyone|Domain Users|pavan" -or
                    $rights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AllExtendedRights|WriteProperty") {
                    if ($ace.AccessControlType -eq "Allow") {
                        "  WHO: $id | RIGHTS: $rights | TYPE: Allow" | Out-File $outputFile -Append
                    }
                }
            }
        }
    } catch { "  Error: $($_.Exception.Message)" | Out-File $outputFile -Append }
}

# Also check ACLs on Domain Admins group itself
"`n--- Domain Admins GROUP ---" | Out-File $outputFile -Append
try {
    $daResult = Run-LDAPQuery -Filter "(&(objectCategory=group)(cn=Domain Admins))" -Properties @("distinguishedname")
    if ($daResult -and $daResult.Count -gt 0) {
        $entry = $daResult[0].GetDirectoryEntry()
        $acl = $entry.ObjectSecurity
        foreach ($ace in $acl.Access) {
            $id = $ace.IdentityReference.ToString()
            $rights = $ace.ActiveDirectoryRights.ToString()
            if ($id -match "Authenticated Users|Everyone|Domain Users|pavan" -or
                $rights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|Self|WriteProperty") {
                if ($ace.AccessControlType -eq "Allow") {
                    "  WHO: $id | RIGHTS: $rights" | Out-File $outputFile -Append
                }
            }
        }
    }
} catch { "  Error: $($_.Exception.Message)" | Out-File $outputFile -Append }

# ============================================================
# 28. MACHINE ACCOUNT QUOTA (can we add computers?)
# ============================================================
Write-Section "28. MACHINE ACCOUNT QUOTA"
try {
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $domainDN = $rootDSE.defaultNamingContext
    $domainEntry = [ADSI]"LDAP://$domainDN"
    $maq = $domainEntry.Properties["ms-DS-MachineAccountQuota"].Value
    "ms-DS-MachineAccountQuota: $maq" | Out-File $outputFile -Append
    if ([int]$maq -gt 0) {
        "** Any domain user can add up to $maq computer accounts! **" | Out-File $outputFile -Append
        "** This enables RBCD attacks if you find a target with write access **" | Out-File $outputFile -Append
        Write-Host "  MachineAccountQuota = $maq (RBCD possible)" -ForegroundColor Yellow
    }
} catch { "Error: $($_.Exception.Message)" | Out-File $outputFile -Append }

# ============================================================
# 29. CERTIFICATE SERVICES (AD CS)
# ============================================================
Write-Section "29. AD CERTIFICATE SERVICES (AD CS)"
try {
    $configDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $cas = Run-LDAPQuery -Filter "(objectClass=pKIEnrollmentService)" -Properties @("cn","dnshostname","certificatetemplates") -SearchBase $configDN
    if ($cas -and $cas.Count -gt 0) {
        foreach ($ca in $cas) {
            $p = $ca.Properties
            "CA: $($p['cn'][0]) | Host: $($p['dnshostname'][0])" | Out-File $outputFile -Append
            "Templates: $($p['certificatetemplates'] -join ', ')" | Out-File $outputFile -Append
        }
        Write-Host "  AD CS found - check for ESC1-ESC8 vulnerabilities" -ForegroundColor Yellow
    } else {
        "No Certificate Authorities found" | Out-File $outputFile -Append
    }

    # Check certificate templates for misconfigurations
    $templates = Run-LDAPQuery -Filter "(objectClass=pKICertificateTemplate)" -Properties @("cn","mspki-certificate-name-flag","mspki-enrollment-flag","pkiextendedkeyusage","mspki-ra-signature","mspki-certificate-application-policy","ntsecuritydescriptor") -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
    if ($templates) {
        "`nCertificate Templates:" | Out-File $outputFile -Append
        foreach ($tmpl in $templates) {
            $p = $tmpl.Properties
            $nameFlag = if($p["mspki-certificate-name-flag"].Count -gt 0){[int]$p["mspki-certificate-name-flag"][0]}else{0}
            $enrollFlag = if($p["mspki-enrollment-flag"].Count -gt 0){[int]$p["mspki-enrollment-flag"][0]}else{0}
            $eku = if($p["pkiextendedkeyusage"].Count -gt 0){$p["pkiextendedkeyusage"] -join "; "}else{""}
            $raSig = if($p["mspki-ra-signature"].Count -gt 0){[int]$p["mspki-ra-signature"][0]}else{0}

            # ESC1: ENROLLEE_SUPPLIES_SUBJECT (0x1) + Client Auth EKU + low RA signature
            $suppliesSubject = ($nameFlag -band 1) -ne 0
            $clientAuth = $eku -match "1.3.6.1.5.5.7.3.2"  # Client Authentication
            $anyPurpose = $eku -match "2.5.29.37.0"
            $noEKU = $eku -eq ""

            if ($suppliesSubject -and ($clientAuth -or $anyPurpose -or $noEKU) -and $raSig -eq 0) {
                "  ** POTENTIALLY VULNERABLE (ESC1): $($p['cn'][0]) **" | Out-File $outputFile -Append
                "     SuppliesSubject: True | ClientAuth: $clientAuth | RASig: $raSig" | Out-File $outputFile -Append
                Write-Host "  POSSIBLE ESC1: $($p['cn'][0])" -ForegroundColor Red
            } else {
                "  Template: $($p['cn'][0]) | SuppliesSubject: $suppliesSubject | EKU: $eku" | Out-File $outputFile -Append
            }
        }
    }
} catch { "Error: $($_.Exception.Message)" | Out-File $outputFile -Append }

# ============================================================
# 30. ORGANIZATIONAL UNITS
# ============================================================
Write-Section "30. ORGANIZATIONAL UNITS"
$ous = Run-LDAPQuery -Filter "(objectCategory=organizationalUnit)" -Properties @("name","distinguishedname","gPLink")
if ($ous) {
    foreach ($ou in $ous) {
        $p = $ou.Properties
        $gplink = if($p["gplink"].Count -gt 0){"$($p['gplink'][0])"}else{"None"}
        "$($p['distinguishedname'][0]) | GPO: $gplink" | Out-File $outputFile -Append
    }
    "`nTotal: $($ous.Count)" | Out-File $outputFile -Append
}

# ============================================================
# 31. SPNS ON COMPUTER ACCOUNTS (more services)
# ============================================================
Write-Section "31. INTERESTING SERVICES (SQL, HTTP, Exchange, etc.)"
$svcComputers = Run-LDAPQuery -Filter "(&(objectCategory=computer)(servicePrincipalName=*))" -Properties @("cn","serviceprincipalname")
if ($svcComputers) {
    $sqlServers = @(); $webServers = @(); $exchangeServers = @()
    foreach ($sc in $svcComputers) {
        $p = $sc.Properties
        $spns = $p["serviceprincipalname"] -join "; "
        if ($spns -match "MSSQL|SQLServer") { $sqlServers += "$($p['cn'][0]) | $spns" }
        if ($spns -match "HTTP/|HTTPS/") { $webServers += "$($p['cn'][0]) | $spns" }
        if ($spns -match "exchange|SMTP") { $exchangeServers += "$($p['cn'][0]) | $spns" }
    }

    "SQL Servers:" | Out-File $outputFile -Append
    foreach ($s in $sqlServers) { "  $s" | Out-File $outputFile -Append }

    "`nWeb Servers:" | Out-File $outputFile -Append
    foreach ($w in $webServers) { "  $w" | Out-File $outputFile -Append }

    "`nExchange Servers:" | Out-File $outputFile -Append
    foreach ($e in $exchangeServers) { "  $e" | Out-File $outputFile -Append }
}

# ============================================================
# 32. SESSIONS ON KEY SERVERS (who is logged in where)
# ============================================================
Write-Section "32. SESSIONS ON KEY SERVERS"
$sessionServers = @("COMPND2K12DC","COMPND-SRV-003","COMPND-VM-PDC","SOLITAIRE")
foreach ($srv in $sessionServers) {
    "`n--- $srv ---" | Out-File $outputFile -Append
    $session = query user /server:$srv 2>&1
    $session | Out-File $outputFile -Append
}

# ============================================================
# 33. DEFENDER / AV STATUS
# ============================================================
Write-Section "33. SECURITY CONTROLS"
"--- Defender ---" | Out-File $outputFile -Append
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    "RealTimeProtection: $($mpStatus.RealTimeProtectionEnabled)" | Out-File $outputFile -Append
    "AMServiceEnabled: $($mpStatus.AMServiceEnabled)" | Out-File $outputFile -Append
    "AntivirusEnabled: $($mpStatus.AntivirusEnabled)" | Out-File $outputFile -Append
    "BehaviorMonitor: $($mpStatus.BehaviorMonitorEnabled)" | Out-File $outputFile -Append
} catch { "Could not query Defender status" | Out-File $outputFile -Append }

"--- AMSI ---" | Out-File $outputFile -Append
$amsiLoaded = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.Location -like "*amsi*" }
"AMSI Loaded: $(if($amsiLoaded){'Yes'}else{'No'})" | Out-File $outputFile -Append

"--- PowerShell Logging ---" | Out-File $outputFile -Append
$sbl = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" 2>$null
$ml = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" 2>$null
$tr = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" 2>$null
"ScriptBlockLogging: $(if($sbl){'Configured'}else{'Not Configured'})" | Out-File $outputFile -Append
"ModuleLogging: $(if($ml){'Configured'}else{'Not Configured'})" | Out-File $outputFile -Append
"Transcription: $(if($tr){'Configured'}else{'Not Configured'})" | Out-File $outputFile -Append

# ============================================================
# 34. LOCAL RECON ON JUMP SERVER
# ============================================================
Write-Section "34. LOCAL RECON - JUMP SERVER"

"--- Installed Software ---" | Out-File $outputFile -Append
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion | Where-Object { $_.DisplayName } |
    Sort-Object DisplayName | Format-Table -AutoSize | Out-String | Out-File $outputFile -Append

"--- Scheduled Tasks ---" | Out-File $outputFile -Append
schtasks /query /fo LIST /v 2>$null | Select-String "TaskName|Run As|Task To Run" | Out-File $outputFile -Append

"--- Running Services ---" | Out-File $outputFile -Append
Get-Service | Where-Object { $_.Status -eq "Running" } | Format-Table Name, DisplayName, StartType -AutoSize | Out-String | Out-File $outputFile -Append

"--- Network Connections ---" | Out-File $outputFile -Append
netstat -ano | Out-File $outputFile -Append

"--- Saved WiFi Profiles ---" | Out-File $outputFile -Append
netsh wlan show profiles 2>$null | Out-File $outputFile -Append

"--- Environment Variables ---" | Out-File $outputFile -Append
Get-ChildItem Env: | Format-Table Name, Value -AutoSize | Out-String | Out-File $outputFile -Append

# ============================================================
# ATTACK PATH SUMMARY
# ============================================================
Write-Section "ATTACK PATH SUMMARY"

$summary = @"

DOMAIN: $domain
CURRENT USER: $env:USERDOMAIN\$env:USERNAME
LOCAL ADMIN: $isLocalAdmin
LANGUAGE MODE: $($ExecutionContext.SessionState.LanguageMode)

--- ATTACK SURFACE ---
Total Users: $($users.Count) (Enabled: $enabledCount)
Total Computers: $($computers.Count)
Admin Accounts (adminCount=1): $($adminUsers.Count)
Kerberoastable: $($spnUsers.Count)
AS-REP Roastable: $($asrepUsers.Count)
Password Never Expires: $($neverExpire.Count)
Stale Accounts: $($staleUsers.Count)
Never Logged On: $($neverLogon.Count)
Old OS Machines: $($oldOS.Count)
LAPS Readable: $($lapsFound.Count)
Unconstrained Delegation: $(if($unconstrained){$unconstrained.Count}else{0})
Constrained Delegation: $(if($constrained){$constrained.Count}else{0})

--- RECOMMENDED ATTACK PATHS ---
1. KERBEROASTING: $($spnUsers.Count) accounts with SPNs - request TGS and crack offline
2. CREDENTIAL HUNTING: Check SYSVOL scripts, user descriptions, shares
3. DELEGATION ABUSE: $(if($unconstrained){$unconstrained.Count}else{0}) unconstrained delegation targets
4. AD CS: Check for ESC1-ESC8 certificate template vulnerabilities
5. PASSWORD SPRAY: Use known pattern against enabled users (respect lockout policy)
6. ACL ABUSE: Check if current user has write rights on high-value objects
7. OLD OS: $($oldOS.Count) machines with outdated OS - check for known exploits

"@

$summary | Out-File $outputFile -Append
$summary | Write-Host -ForegroundColor Green

Write-Host "`n" -NoNewline
Write-Host "=" * 50 -ForegroundColor Green
Write-Host "  ENUMERATION COMPLETE" -ForegroundColor Green
Write-Host "  Results: $outputFile" -ForegroundColor Green
Write-Host "=" * 50 -ForegroundColor Green
