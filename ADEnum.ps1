<#
.SYNOPSIS
    ADEnum - Windows / Active Directory Enumeration Module
.DESCRIPTION
    Enumerates local users, domain users, computers, groups, GPOs, password
    policies, shares, services, delegation, GPP passwords and more.
    Outputs JSON + self-contained HTML report.
    All queries use native LDAP — no RSAT module required.

    Usage: Import-Module .\ADEnum.ps1
           Invoke-FullEnum
           Get-ADEnumHelp
.NOTES
    Version : 1.0
    Requires: PowerShell 5.1+
#>

#region ==================== CORE ====================

$Script:Banner = @"

     _    ____  _____
    / \  |  _ \| ____|_ __  _   _ _ __ ___
   / _ \ | | | |  _| | '_ \| | | | '_ `` _ \
  / ___ \| |_| | |___| | | | |_| | | | | | |
 /_/   \_\____/|_____|_| |_|\__,_|_| |_| |_|
                                        v1.0
"@

$Script:OutputDir = $null
$Script:Timestamp = $null
$Script:Report = @{}
$Script:Findings = [System.Collections.ArrayList]@()

$Script:AssignPat = '(?i)(?:pass|pwd|password|passwd|cred|credential|secret|pin|key|token|login|logon|senha)\s*[=:]\s*\S+'
$Script:StandPat = '(?i)(?:changeme|change me|Welcome1|Welcome!|P@ss|P@ssw0rd|Password1|Passw0rd|123456|qwerty|letmein|admin123|temp pass|default pass|initial pass|reset pass)'
$Script:SensPat = "(?:${Script:AssignPat})|(?:${Script:StandPat})"

function Initialize-ADEnum {
    $Script:OutputDir = Join-Path $PWD "ADEnum_Results"
    $Script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:Report = @{}
    $Script:Findings = [System.Collections.ArrayList]@()
    if (-not (Test-Path $Script:OutputDir)) { New-Item -ItemType Directory -Path $Script:OutputDir -Force | Out-Null }
}

function Write-Status { param([string]$S,[string]$M,[string]$C="White"); Write-Host "  [$S] " -ForegroundColor DarkGray -NoNewline; Write-Host $M -ForegroundColor $C }
function Add-Finding { param([string]$Sev,[string]$T,[string]$D); $Script:Findings.Add(@{severity=$Sev;title=$T;detail=$D}) | Out-Null; $c=if($Sev -eq 'high'){'Red'}else{'Yellow'}; Write-Host "  [!] $T" -ForegroundColor $c }
function Test-SensitiveDesc { param([string]$Desc,[string]$Id); if($Desc -and $Desc -match $Script:SensPat){ $h=[regex]::Matches($Desc,$Script:SensPat); $m=($h|ForEach-Object{$_.Value.Trim()})-join', '; Write-Host "  [!!!] ${Id}: `"${Desc}`"" -ForegroundColor Red } }

#endregion

#region ==================== ENUM FUNCTIONS ====================

function Get-SystemInfo {
    $os=Get-CimInstance Win32_OperatingSystem; $cs=Get-CimInstance Win32_ComputerSystem
    $dn="N/A";try{$dn=$cs.Domain}catch{}; $dj=$false;try{$dj=$cs.PartOfDomain}catch{}
    $adm=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $data=[ordered]@{hostname=$env:COMPUTERNAME;user="$env:USERDOMAIN\$env:USERNAME";os=$os.Caption;version=$os.Version;build=$os.BuildNumber;arch=$os.OSArchitecture;domain=$dn;partOfDomain=$dj;lastBoot=$os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss');psVersion=$PSVersionTable.PSVersion.ToString();isAdmin=$adm}
    $Script:Report.SystemInfo=$data
    Write-Status "system" "$($data.hostname) | $($data.os) | admin=$adm" "Cyan"
}

function Get-DomainContext {
    try {
        $dom=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $for=[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $data=[ordered]@{domain=$dom.Name;forest=$for.Name;dcs=@($dom.DomainControllers|ForEach-Object{$_.Name});forestDomains=@($for.Domains|ForEach-Object{$_.Name});domainMode=$dom.DomainMode.ToString();forestMode=$for.ForestMode.ToString();pdc=$dom.PdcRoleOwner.Name;schema=$for.SchemaRoleOwner.Name;naming=$for.NamingRoleOwner.Name;rid=$dom.RidRoleOwner.Name;infra=$dom.InfrastructureRoleOwner.Name}
        $Script:Report.DomainContext=$data
        Write-Status "domain" "$($data.domain) | DCs: $($data.dcs -join ', ')" "Cyan"
    } catch { Write-Status "domain" "could not retrieve: $($_.Exception.Message)" "Red" }
}

function Get-LocalUsersEnum {
    try {
        $users=@(Get-LocalUser|ForEach-Object{$u=$_; Test-SensitiveDesc -Desc $u.Description -Id $u.Name
            [ordered]@{name=$u.Name;fullName=$u.FullName;description=$u.Description;enabled=$u.Enabled;pwdLastSet=$(if($u.PasswordLastSet){$u.PasswordLastSet.ToString('yyyy-MM-dd')}else{$null});lastLogon=$(if($u.LastLogon){$u.LastLogon.ToString('yyyy-MM-dd')}else{$null});sid=$u.SID.Value}
        })
        $Script:Report.LocalUsers=$users
        Write-Status "local-users" "$($users.Count) total, $(@($users|Where-Object{$_.enabled}).Count) enabled" "White"
    } catch { Write-Status "local-users" "error: $($_.Exception.Message)" "Red" }
}

function Get-LocalAdmins {
    $admins=@()
    try { $admins=@(Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop|ForEach-Object{[ordered]@{name=$_.Name;class=$_.ObjectClass;source=$_.PrincipalSource.ToString()}}) } catch {
        try { $admins=@(Get-LocalGroupMember -Group "Administradores" -ErrorAction Stop|ForEach-Object{[ordered]@{name=$_.Name;class=$_.ObjectClass;source=$_.PrincipalSource.ToString()}}) } catch {
            try { $raw=net localgroup Administrators 2>$null; if(-not $raw){$raw=net localgroup Administradores 2>$null}; if($raw){$inM=$false; foreach($l in $raw){if($l-match'^---'){$inM=$true;continue};if($l-match'^The command completed'){break};if($inM-and $l.Trim()){$admins+=[ordered]@{name=$l.Trim();class="Unknown";source="net"}}}} } catch {}
    }}
    $Script:Report.LocalAdmins=$admins
    Write-Status "local-admins" "$($admins.Count) members" "White"
}

function Get-DomainUsersLDAP {
    param([string]$Filter="(&(objectCategory=person)(objectClass=user))",[string]$Label="domain-users")
    try {
        $s=New-Object System.DirectoryServices.DirectorySearcher; $s.Filter=$Filter; $s.PageSize=1000
        @("samaccountname","displayname","mail","description","memberof","whencreated","lastlogon","pwdlastset","useraccountcontrol","admincount","distinguishedname","department","title")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $results=$s.FindAll(); $users=@(); $sc=0
        foreach($r in $results){$p=$r.Properties; $uac=if($p["useraccountcontrol"]){$p["useraccountcontrol"][0]}else{0}; $sam=($p["samaccountname"]|Select-Object -First 1); $desc=($p["description"]|Select-Object -First 1)
            Test-SensitiveDesc -Desc $desc -Id $sam; if($desc -and $desc -match $Script:SensPat){$sc++}
            $ll="Never";if($p["lastlogon"]-and$p["lastlogon"][0]){try{$ll=[DateTime]::FromFileTime($p["lastlogon"][0]).ToString('yyyy-MM-dd')}catch{}}
            $ps="Never";if($p["pwdlastset"]-and$p["pwdlastset"][0]-and$p["pwdlastset"][0]-gt 0){try{$ps=[DateTime]::FromFileTime($p["pwdlastset"][0]).ToString('yyyy-MM-dd')}catch{}}
            $mo=@();if($p["memberof"]){$mo=@($p["memberof"]|ForEach-Object{($_ -split ',')[0]-replace 'CN=',''})}
            $users+=[ordered]@{sam=$sam;displayName=($p["displayname"]|Select-Object -First 1);email=($p["mail"]|Select-Object -First 1);description=$desc;department=($p["department"]|Select-Object -First 1);title=($p["title"]|Select-Object -First 1);enabled=(-not[bool]($uac-band 0x0002));adminCount=($p["admincount"]|Select-Object -First 1);created=($p["whencreated"]|Select-Object -First 1).ToString('yyyy-MM-dd');lastLogon=$ll;pwdLastSet=$ps;memberOf=($mo-join'; ');dn=($p["distinguishedname"]|Select-Object -First 1)}
        }
        Write-Status $Label "$($users.Count) found, $(@($users|Where-Object{$_.enabled}).Count) enabled" "White"
        if($sc -gt 0){Write-Host "  [!!!] $sc account(s) with sensitive descriptions" -ForegroundColor Red}
        return $users
    } catch { Write-Status $Label "LDAP error: $($_.Exception.Message)" "Red"; return @() }
}

function Get-DomainAdmins {
    $groups=@("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","DnsAdmins","Group Policy Creator Owners")
    $all=@()
    foreach($g in $groups){try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=group)(cn=$g))";$s.PropertiesToLoad.Add("member")|Out-Null;$r=$s.FindOne()
        if($r -and $r.Properties["member"]){foreach($m in $r.Properties["member"]){$mn=($m-split',')[0]-replace'CN=','';$all+=[ordered]@{group=$g;member=$mn;dn=$m}}}}catch{}}
    $Script:Report.PrivilegedAccounts=$all
    $uniq=@($all|ForEach-Object{$_.member}|Sort-Object -Unique)
    Write-Status "admins" "$($all.Count) memberships, $($uniq.Count) unique accounts" "White"
}

function Get-SensitiveDescriptions {
    $cats=@(@{n="Users";f="(&(objectCategory=person)(objectClass=user)(description=*))"},@{n="Computers";f="(&(objectCategory=computer)(description=*))"},@{n="Groups";f="(&(objectCategory=group)(description=*))"})
    $finds=@()
    foreach($c in $cats){try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter=$c.f;$s.PageSize=1000;@("samaccountname","cn","description","distinguishedname")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        foreach($r in $s.FindAll()){$p=$r.Properties;$desc=($p["description"]|Select-Object -First 1);$name=($p["samaccountname"]|Select-Object -First 1);if(-not $name){$name=($p["cn"]|Select-Object -First 1)}
            if($desc -and $desc -match $Script:SensPat){$h=[regex]::Matches($desc,$Script:SensPat);$matched=($h|ForEach-Object{$_.Value.Trim()})-join', ';Write-Host "  [!!!] $($c.n): ${name} => `"${desc}`"" -ForegroundColor Red
                $finds+=[ordered]@{type=$c.n;identity=$name;description=$desc;matched=$matched;dn=($p["distinguishedname"]|Select-Object -First 1)}}}}catch{}}
    $Script:Report.SensitiveDescriptions=$finds
    if($finds.Count -gt 0){Add-Finding "high" "$($finds.Count) object(s) with credentials in description" "Plaintext passwords or tokens in AD description attributes"}
    else{Write-Status "sensitive" "0 findings (clean)" "Green"}
}

function Get-InactiveAccounts {
    param([int]$Days=90)
    $cutoff=(Get-Date).AddDays(-$Days).ToFileTime()
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=person)(objectClass=user)(lastLogon<=$cutoff))";$s.PageSize=1000
        @("samaccountname","lastlogon","useraccountcontrol","whencreated","description")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $accts=@();foreach($r in $s.FindAll()){$p=$r.Properties;$uac=if($p["useraccountcontrol"]){$p["useraccountcontrol"][0]}else{0}
            $ll="Never";if($p["lastlogon"]-and$p["lastlogon"][0]){try{$ll=[DateTime]::FromFileTime($p["lastlogon"][0]).ToString('yyyy-MM-dd')}catch{}}
            $accts+=[ordered]@{sam=($p["samaccountname"]|Select-Object -First 1);lastLogon=$ll;enabled=(-not[bool]($uac-band 0x0002));created=($p["whencreated"]|Select-Object -First 1).ToString('yyyy-MM-dd');description=($p["description"]|Select-Object -First 1)}}
        $Script:Report.InactiveAccounts=$accts
        $ei=@($accts|Where-Object{$_.enabled}).Count
        Write-Status "inactive" "$($accts.Count) accounts (>$Days days), $ei still enabled" "White"
        if($ei -gt 0){Add-Finding "medium" "$ei enabled account(s) inactive $Days+ days" "Dormant: $(($accts|Where-Object{$_.enabled}|ForEach-Object{$_.sam})-join', ')"}
    }catch{Write-Status "inactive" "error: $($_.Exception.Message)" "Red"}
}

function Get-NeverExpirePasswords {
    $users=Get-DomainUsersLDAP -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -Label "pwd-no-expire"
    $Script:Report.NeverExpirePasswords=$users
    if($users.Count -gt 0){Add-Finding "medium" "$($users.Count) account(s) with password never expire" "Accounts: $(($users|ForEach-Object{$_.sam})-join', ')"}
}

function Get-KerberoastableAccounts {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))";$s.PageSize=1000
        @("samaccountname","serviceprincipalname","description","admincount","pwdlastset","memberof")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $spn=@();foreach($r in $s.FindAll()){$p=$r.Properties;$sam=($p["samaccountname"]|Select-Object -First 1)
            $ps="Never";if($p["pwdlastset"]-and$p["pwdlastset"][0]-and$p["pwdlastset"][0]-gt 0){try{$ps=[DateTime]::FromFileTime($p["pwdlastset"][0]).ToString('yyyy-MM-dd')}catch{}}
            Test-SensitiveDesc -Desc ($p["description"]|Select-Object -First 1) -Id $sam
            if($ps-ne"Never"-and[DateTime]::Parse($ps)-lt(Get-Date).AddYears(-1)){Write-Host "  [!] ${sam}: password not rotated since ${ps}" -ForegroundColor Yellow}
            $spn+=[ordered]@{sam=$sam;spns=($p["serviceprincipalname"]-join'; ');adminCount=($p["admincount"]|Select-Object -First 1);pwdLastSet=$ps;description=($p["description"]|Select-Object -First 1)}}
        $Script:Report.Kerberoastable=$spn
        Write-Status "kerberoast" "$($spn.Count) account(s) with SPN" "White"
    }catch{Write-Status "kerberoast" "error: $($_.Exception.Message)" "Red"}
}

function Get-ASREPRoastableAccounts {
    $users=Get-DomainUsersLDAP -Filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Label "asrep-roast"
    $Script:Report.ASREPRoastable=$users
    if($users.Count -gt 0){Add-Finding "high" "$($users.Count) account(s) AS-REP roastable" "No pre-auth: $(($users|ForEach-Object{$_.sam})-join', ')"}
}

function Get-DomainComputers {
    param([string]$OSFilter="*")
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=computer)(operatingSystem=$OSFilter))";$s.PageSize=1000
        @("cn","dnshostname","operatingsystem","operatingsystemversion","lastlogon","whencreated","description","distinguishedname","useraccountcontrol")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $comps=@();foreach($r in $s.FindAll()){$p=$r.Properties;$cn=($p["cn"]|Select-Object -First 1);$desc=($p["description"]|Select-Object -First 1);$uac=if($p["useraccountcontrol"]){$p["useraccountcontrol"][0]}else{0}
            Test-SensitiveDesc -Desc $desc -Id $cn
            $ll="Never";if($p["lastlogon"]-and$p["lastlogon"][0]){try{$ll=[DateTime]::FromFileTime($p["lastlogon"][0]).ToString('yyyy-MM-dd')}catch{}}
            $comps+=[ordered]@{name=$cn;fqdn=($p["dnshostname"]|Select-Object -First 1);os=($p["operatingsystem"]|Select-Object -First 1);osVer=($p["operatingsystemversion"]|Select-Object -First 1);enabled=(-not[bool]($uac-band 0x0002));lastLogon=$ll;created=($p["whencreated"]|Select-Object -First 1).ToString('yyyy-MM-dd');description=$desc;ou=(($p["distinguishedname"]|Select-Object -First 1)-replace'^CN=[^,]+,','')}}
        $Script:Report.Computers=$comps
        Write-Status "computers" "$($comps.Count) found" "White"
    }catch{Write-Status "computers" "error: $($_.Exception.Message)" "Red"}
}

function Get-DomainControllers {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";$s.PageSize=1000
        @("cn","dnshostname","operatingsystem","operatingsystemversion","description")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $dcs=@();foreach($r in $s.FindAll()){$p=$r.Properties;$dcs+=[ordered]@{name=($p["cn"]|Select-Object -First 1);fqdn=($p["dnshostname"]|Select-Object -First 1);os=($p["operatingsystem"]|Select-Object -First 1);osVer=($p["operatingsystemversion"]|Select-Object -First 1);description=($p["description"]|Select-Object -First 1)}}
        $Script:Report.DomainControllers=$dcs; Write-Status "dcs" "$($dcs.Count) domain controller(s)" "White"
    }catch{Write-Status "dcs" "error: $($_.Exception.Message)" "Red"}
}

function Get-PasswordPolicy {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(objectClass=domainDNS)"
        @("minPwdLength","minPwdAge","maxPwdAge","pwdHistoryLength","lockoutThreshold","lockoutDuration","lockOutObservationWindow","pwdProperties")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $r=$s.FindOne();$p=$r.Properties;$ml=$p["minpwdlength"][0];$lt=$p["lockoutthreshold"][0];$cx=[bool]($p["pwdproperties"][0]-band 1)
        $data=[ordered]@{minLength=$ml;minAge="$([TimeSpan]::FromTicks([Math]::Abs($p["minpwdage"][0])).Days) days";maxAge="$([TimeSpan]::FromTicks([Math]::Abs($p["maxpwdage"][0])).Days) days";history=$p["pwdhistorylength"][0];lockoutThreshold=$lt;lockoutDuration="$([TimeSpan]::FromTicks([Math]::Abs($p["lockoutduration"][0])).Minutes) min";lockoutWindow="$([TimeSpan]::FromTicks([Math]::Abs($p["lockoutobservationwindow"][0])).Minutes) min";complexityRequired=$cx}
        $Script:Report.PasswordPolicy=$data
        Write-Status "policy" "minLen=$ml lockout=$lt complexity=$cx" "White"
        if($ml -lt 12){Add-Finding "high" "Password min length is $ml (recommended: 12+)" "Short passwords are trivially cracked offline"}
        if($lt -eq 0){Add-Finding "high" "No account lockout threshold" "Unlimited brute-force attempts"}
        if(-not $cx){Add-Finding "medium" "Password complexity not required" "Simple passwords allowed"}
    }catch{Write-Status "policy" "error: $($_.Exception.Message)" "Red"}
}

function Get-DomainGroupsEnum {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=group))";$s.PageSize=1000
        @("cn","description","member","grouptype","whencreated","admincount")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $groups=@();foreach($r in $s.FindAll()){$p=$r.Properties;$ml=@();if($p["member"]){$ml=@($p["member"]|ForEach-Object{($_ -split ',')[0]-replace'CN=',''})}
            $groups+=[ordered]@{name=($p["cn"]|Select-Object -First 1);description=($p["description"]|Select-Object -First 1);memberCount=$ml.Count;members=($ml-join'; ');adminCount=($p["admincount"]|Select-Object -First 1);created=($p["whencreated"]|Select-Object -First 1).ToString('yyyy-MM-dd')}}
        $Script:Report.Groups=$groups; Write-Status "groups" "$($groups.Count) total, $(@($groups|Where-Object{$_.memberCount -gt 0}).Count) populated" "White"
    }catch{Write-Status "groups" "error: $($_.Exception.Message)" "Red"}
}

function Get-OUStructure {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(objectCategory=organizationalUnit)";$s.PageSize=1000
        @("ou","description","distinguishedname","whencreated","gplink")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $ous=@();foreach($r in $s.FindAll()){$p=$r.Properties;$gpos=@();if($p["gplink"]){$gpos=@([regex]::Matches($p["gplink"][0],'\{[^}]+\}')|ForEach-Object{$_.Value})}
            $ous+=[ordered]@{name=($p["ou"]|Select-Object -First 1);dn=($p["distinguishedname"]|Select-Object -First 1);description=($p["description"]|Select-Object -First 1);created=($p["whencreated"]|Select-Object -First 1).ToString('yyyy-MM-dd');linkedGPOs=($gpos-join'; ')}}
        $Script:Report.OUs=$ous; Write-Status "ous" "$($ous.Count) organizational units" "White"
    }catch{Write-Status "ous" "error: $($_.Exception.Message)" "Red"}
}

function Get-GPOInfo {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(objectCategory=groupPolicyContainer)";$s.PageSize=1000
        @("displayname","cn","gpcfilesyspath","whencreated","whenchanged","flags")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $gpos=@();foreach($r in $s.FindAll()){$p=$r.Properties;$fl=if($p["flags"]){$p["flags"][0]}else{0};$st=switch($fl){0{"Enabled"}1{"User Disabled"}2{"Computer Disabled"}3{"All Disabled"}default{"Unknown"}}
            $gpos+=[ordered]@{name=($p["displayname"]|Select-Object -First 1);guid=($p["cn"]|Select-Object -First 1);status=$st;sysvolPath=($p["gpcfilesyspath"]|Select-Object -First 1);created=($p["whencreated"]|Select-Object -First 1).ToString('yyyy-MM-dd');lastChanged=($p["whenchanged"]|Select-Object -First 1).ToString('yyyy-MM-dd')}}
        $Script:Report.GPOs=$gpos; Write-Status "gpos" "$($gpos.Count) GPOs" "White"
    }catch{Write-Status "gpos" "error: $($_.Exception.Message)" "Red"}
}

function Get-DomainTrusts {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(objectCategory=trustedDomain)"
        @("cn","trustdirection","trusttype","flatname","whencreated")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $trusts=@();foreach($r in $s.FindAll()){$p=$r.Properties;$dir=switch($p["trustdirection"][0]){0{"Disabled"}1{"Inbound"}2{"Outbound"}3{"Bidirectional"}default{"Unknown"}};$typ=switch($p["trusttype"][0]){1{"Downlevel"}2{"Uplevel (AD)"}3{"MIT (Kerberos)"}default{"Unknown"}}
            $trusts+=[ordered]@{domain=($p["cn"]|Select-Object -First 1);netbios=($p["flatname"]|Select-Object -First 1);direction=$dir;type=$typ}}
        $Script:Report.Trusts=$trusts; Write-Status "trusts" "$($trusts.Count) trust(s)" "White"
    }catch{Write-Status "trusts" "error: $($_.Exception.Message)" "Red"}
}

function Get-DNSRecords {
    try{$domain=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name;$base="DC=$($domain.Replace('.',',DC='))"
        $s=New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=MicrosoftDNS,DC=DomainDnsZones,$base");$s.Filter="(objectClass=dnsNode)";$s.PageSize=1000
        @("dc","distinguishedname")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        $recs=@();foreach($r in $s.FindAll()){$p=$r.Properties;$recs+=[ordered]@{name=($p["dc"]|Select-Object -First 1);dn=($p["distinguishedname"]|Select-Object -First 1)}}
        $Script:Report.DNS=$recs; Write-Status "dns" "$($recs.Count) records" "White"
    }catch{Write-Status "dns" "error: $($_.Exception.Message)" "Red"}
}

function Get-UnconstrainedDelegation {
    $results=@()
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        @("cn","dnshostname","operatingsystem","distinguishedname")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        foreach($r in $s.FindAll()){$p=$r.Properties;$results+=[ordered]@{type="Computer";identity=($p["cn"]|Select-Object -First 1);fqdn=($p["dnshostname"]|Select-Object -First 1);os=($p["operatingsystem"]|Select-Object -First 1);dn=($p["distinguishedname"]|Select-Object -First 1)}}}catch{}
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        @("samaccountname","distinguishedname")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        foreach($r in $s.FindAll()){$p=$r.Properties;$results+=[ordered]@{type="User";identity=($p["samaccountname"]|Select-Object -First 1);fqdn="";os="";dn=($p["distinguishedname"]|Select-Object -First 1)}}}catch{}
    $Script:Report.UnconstrainedDelegation=$results
    $nonDC=@($results|Where-Object{$_.dn -notmatch 'Domain Controllers'})
    Write-Status "unconstrained" "$($results.Count) object(s), $($nonDC.Count) non-DC" "White"
    if($nonDC.Count -gt 0){Add-Finding "high" "$($nonDC.Count) non-DC with unconstrained delegation" "$(($nonDC|ForEach-Object{$_.identity})-join', ')"}
}

function Get-ConstrainedDelegation {
    $results=@()
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=*)(msDS-AllowedToDelegateTo=*))";$s.PageSize=1000
        @("samaccountname","cn","msds-allowedtodelegateto","objectcategory","useraccountcontrol","distinguishedname")|ForEach-Object{$s.PropertiesToLoad.Add($_)|Out-Null}
        foreach($r in $s.FindAll()){$p=$r.Properties;$name=($p["samaccountname"]|Select-Object -First 1);if(-not $name){$name=($p["cn"]|Select-Object -First 1)}
            $uac=if($p["useraccountcontrol"]){$p["useraccountcontrol"][0]}else{0};$proto=if($uac-band 0x1000000){"Any (Protocol Transition)"}else{"Kerberos Only"}
            $targets=@($p["msds-allowedtodelegateto"])
            $results+=[ordered]@{identity=$name;protocol=$proto;targets=($targets-join'; ');dn=($p["distinguishedname"]|Select-Object -First 1)}}}catch{}
    $Script:Report.ConstrainedDelegation=$results
    $ptrans=@($results|Where-Object{$_.protocol -eq "Any (Protocol Transition)"})
    Write-Status "constrained" "$($results.Count) object(s) with constrained delegation" "White"
    if($ptrans.Count -gt 0){Add-Finding "medium" "$($ptrans.Count) object(s) with protocol transition" "Can impersonate any user to target services: $(($ptrans|ForEach-Object{$_.identity})-join', ')"}
}

function Get-MachineAccountQuota {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(objectClass=domainDNS)";$s.PropertiesToLoad.Add("ms-DS-MachineAccountQuota")|Out-Null
        $r=$s.FindOne();$maq=$r.Properties["ms-ds-machineaccountquota"][0]
        $Script:Report.MachineAccountQuota=$maq
        Write-Status "maq" "ms-DS-MachineAccountQuota = $maq" "White"
        if($maq -gt 0){Add-Finding "medium" "Machine account quota is $maq" "Any domain user can add up to $maq computer accounts (resource-based constrained delegation attack vector)"}
    }catch{Write-Status "maq" "error: $($_.Exception.Message)" "Red"}
}

function Get-LAPSStatus {
    try{$s=New-Object System.DirectoryServices.DirectorySearcher;$s.Filter="(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))";$s.PageSize=1000
        $s.PropertiesToLoad.Add("cn")|Out-Null;$s.PropertiesToLoad.Add("ms-Mcs-AdmPwd")|Out-Null;$s.PropertiesToLoad.Add("ms-Mcs-AdmPwdExpirationTime")|Out-Null
        $laps=@();foreach($r in $s.FindAll()){$p=$r.Properties;$laps+=[ordered]@{computer=($p["cn"]|Select-Object -First 1);password=($p["ms-mcs-admpwd"]|Select-Object -First 1);expires=($p["ms-mcs-admpwdexpirationtime"]|Select-Object -First 1)}}
        $Script:Report.LAPS=$laps
        if($laps.Count -gt 0){Write-Status "laps" "$($laps.Count) machine(s) with LAPS readable!" "Red"; Add-Finding "high" "LAPS passwords readable for $($laps.Count) computer(s)" "Current user can read LAPS passwords: $(($laps|ForEach-Object{$_.computer})-join', ')"}
        else{
            $s2=New-Object System.DirectoryServices.DirectorySearcher;$s2.Filter="(&(objectCategory=attributeSchema)(cn=ms-Mcs-AdmPwd))"
            $hasLaps=$s2.FindOne();if($hasLaps){Write-Status "laps" "deployed but not readable (good)" "Green"}else{Write-Status "laps" "not deployed" "Yellow";Add-Finding "medium" "LAPS not deployed" "Local admin passwords are likely shared or static across machines"}}
    }catch{Write-Status "laps" "error or not deployed" "Yellow"}
}

function Get-GPPPasswords {
    Write-Status "gpp" "scanning SYSVOL for cpassword..." "White"
    try{$domain=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        $sysvolPath="\\${domain}\SYSVOL\${domain}\Policies"
        $xmlFiles=@(Get-ChildItem -Path $sysvolPath -Recurse -Include "Groups.xml","Services.xml","ScheduledTasks.xml","DataSources.xml","Drives.xml","Printers.xml" -ErrorAction SilentlyContinue)
        $gppFinds=@()
        foreach($f in $xmlFiles){$content=Get-Content $f.FullName -ErrorAction SilentlyContinue
            if($content -match 'cpassword="([^"]+)"'){$matches_result=[regex]::Matches(($content-join''),'cpassword="([^"]+)"')
                foreach($match in $matches_result){if($match.Groups[1].Value){$gppFinds+=[ordered]@{file=$f.FullName;cpassword=$match.Groups[1].Value}}}}}
        $Script:Report.GPPPasswords=$gppFinds
        if($gppFinds.Count -gt 0){Write-Status "gpp" "$($gppFinds.Count) GPP password(s) found!" "Red"; Add-Finding "high" "Group Policy Preferences passwords found (MS14-025)" "Encrypted cpassword values in SYSVOL — trivially decryptable. Files: $(($gppFinds|ForEach-Object{Split-Path $_.file -Leaf})-join', ')"}
        else{Write-Status "gpp" "clean — no cpassword found" "Green"}
    }catch{Write-Status "gpp" "could not scan SYSVOL: $($_.Exception.Message)" "Yellow"}
}

function Get-AVStatus {
    $avProducts=@()
    try{$av=Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
        foreach($a in $av){$state=$a.productState;$enabled=($state-band 0x1000) -ne 0;$updated=($state-band 0x10) -eq 0
            $avProducts+=[ordered]@{name=$a.displayName;enabled=$enabled;updated=$updated;path=$a.pathToSignedProductExe}}}catch{}
    $services=@("MsMpSvc","WinDefend","Sense","CrowdStrike","CSFalconService","CylanceSvc","SentinelAgent","SentinelOne","SophosAgent","SEPMasterService","McAfeeFramework","cbdefense","CarbonBlack","EPSecurityService","ERAAgent") 
    $running=@()
    foreach($svc in $services){try{$s=Get-Service -Name $svc -ErrorAction SilentlyContinue;if($s){$running+=[ordered]@{name=$svc;displayName=$s.DisplayName;status=$s.Status.ToString()}}}catch{}}
    $procs=@("MsMpEng","MsSense","CSFalconService","CylanceSvc","SentinelAgent","SophosHealth","mcshield","cbdefense","RepMgr","EPSecurityService","ERAAgent")
    $activeProcs=@()
    foreach($proc in $procs){try{$p=Get-Process -Name $proc -ErrorAction SilentlyContinue;if($p){$activeProcs+=[ordered]@{name=$proc;pid=$p[0].Id}}}catch{}}
    $Script:Report.Security=[ordered]@{avProducts=$avProducts;securityServices=$running;securityProcesses=$activeProcs}
    $total=$avProducts.Count+$running.Count+$activeProcs.Count
    if($total -gt 0){Write-Status "security" "$($avProducts.Count) AV, $($running.Count) security services, $($activeProcs.Count) EDR processes" "Yellow"}
    else{Write-Status "security" "no AV/EDR detected" "Green"}
}

function Get-NetworkShares {
    param([string]$ComputerName=$env:COMPUTERNAME)
    try{$shares=@(Get-CimInstance -ClassName Win32_Share -ComputerName $ComputerName|ForEach-Object{[ordered]@{name=$_.Name;path=$_.Path;description=$_.Description;type=$_.Type}})
        $Script:Report.Shares=$shares; Write-Status "shares" "$($shares.Count) on $ComputerName" "White"
    }catch{Write-Status "shares" "error: $($_.Exception.Message)" "Red"}
}

function Get-NetConnections {
    try{$conns=@(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue|ForEach-Object{$proc=try{(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}catch{"unknown"}
            [ordered]@{localAddr=$_.LocalAddress;localPort=$_.LocalPort;remoteAddr=$_.RemoteAddress;remotePort=$_.RemotePort;process=$proc;pid=$_.OwningProcess}})
        $Script:Report.Connections=$conns; Write-Status "connections" "$($conns.Count) established" "White"
    }catch{Write-Status "connections" "error: $($_.Exception.Message)" "Red"}
}

function Get-InterestingServices {
    $defaults=@("LocalSystem","NT AUTHORITY\LocalService","NT AUTHORITY\NetworkService","NT Authority\LocalService","NT Authority\NetworkService","localsystem","Local Service","Network Service")
    try{$svcs=@(Get-CimInstance Win32_Service|Where-Object{$_.StartName -and $_.StartName -notin $defaults}|ForEach-Object{$uq=($_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s')
            if($uq){Write-Host "  [!] UNQUOTED: $($_.Name) => $($_.PathName)" -ForegroundColor Yellow}
            [ordered]@{name=$_.Name;displayName=$_.DisplayName;state=$_.State;startName=$_.StartName;pathName=$_.PathName;unquotedPath=$uq}})
        $Script:Report.Services=$svcs; $uq=@($svcs|Where-Object{$_.unquotedPath}).Count
        Write-Status "services" "$($svcs.Count) non-default RunAs" "White"
        if($uq -gt 0){Add-Finding "medium" "$uq service(s) with unquoted path" "Privilege escalation via unquoted service path"}
    }catch{Write-Status "services" "none found or error" "White"}
}

function Get-ScheduledTasksEnum {
    try{$tasks=@(Get-ScheduledTask|Where-Object{$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'}|ForEach-Object{$info=$_|Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [ordered]@{name=$_.TaskName;state=$_.State.ToString();runAs=$_.Principal.UserId;action=(($_.Actions|ForEach-Object{$_.Execute})-join'; ');lastRun=$(if($info.LastRunTime){$info.LastRunTime.ToString('yyyy-MM-dd HH:mm')}else{$null})}})
        $Script:Report.ScheduledTasks=$tasks; Write-Status "tasks" "$($tasks.Count) non-Microsoft tasks" "White"
    }catch{Write-Status "tasks" "error: $($_.Exception.Message)" "Red"}
}

#endregion

#region ==================== EXPORT ====================

function Export-JSON {
    $jsonPath=Join-Path $Script:OutputDir "ADEnum_$($Script:Report.SystemInfo.domain)_${Script:Timestamp}.json"
    $Script:Report.Findings=@($Script:Findings)
    $Script:Report.Meta=[ordered]@{tool="ADEnum";version="1.0";timestamp=(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss');host=$env:COMPUTERNAME;user="$env:USERDOMAIN\$env:USERNAME"}
    $Script:Report|ConvertTo-Json -Depth 10 -Compress|Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "`n  [+] JSON: $jsonPath" -ForegroundColor Green
}

function Export-HTMLReport {
    $htmlPath=Join-Path $Script:OutputDir "ADEnum_$($Script:Report.SystemInfo.domain)_${Script:Timestamp}.html"
    $jsonStr=$Script:Report|ConvertTo-Json -Depth 10 -Compress
    $jsonB64=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($jsonStr))
    $domainName = $Script:Report.SystemInfo.domain

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>ADEnum - ${domainName}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}::selection{background:#c0392b;color:#fff}
body{font-family:'Inter',system-ui,sans-serif;background:#101010;color:#d1d1d1;font-size:15px;line-height:1.65;-webkit-font-smoothing:antialiased}
.page{max-width:1400px;margin:0 auto;padding:32px 36px 80px}
.top{display:flex;justify-content:space-between;align-items:center;padding:24px 0;margin-bottom:32px;flex-wrap:wrap;gap:16px}
.top-left{display:flex;align-items:center;gap:16px}
.logo{width:36px;height:36px;background:#c0392b;border-radius:6px;display:flex;align-items:center;justify-content:center}
.logo svg{width:18px;height:18px;fill:#fff}
.top-title{font-family:'Geist Mono',monospace;font-weight:700;font-size:22px;color:#fff;letter-spacing:-.02em}
.top-title span{color:#c0392b}
.top-meta{font-family:'Geist Mono',monospace;font-size:13px;color:#666;line-height:1.7}.top-meta b{color:#999;font-weight:500}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:1px;background:#1a1a1a;border-radius:10px;overflow:hidden;margin-bottom:36px}
.sc{background:#151515;padding:22px 24px;text-align:center}
.sv{font-family:'Geist Mono',monospace;font-size:32px;font-weight:700;color:#eee}.sv.crit{color:#e74c3c}.sv.safe{color:#27ae60}
.sl{font-size:12px;color:#666;margin-top:6px;font-weight:500;text-transform:uppercase;letter-spacing:.05em}
.pills{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:32px}
.pills a{font-family:'Geist Mono',monospace;font-size:12px;font-weight:500;color:#777;background:#181818;border:1px solid #222;text-decoration:none;padding:7px 14px;border-radius:6px;transition:all .15s}
.pills a:hover{color:#fff;background:#1e1e1e;border-color:#444}
.togall{font-family:'Geist Mono',monospace;font-size:12px;font-weight:500;color:#888;background:#181818;border:1px solid #222;padding:7px 14px;border-radius:6px;cursor:pointer;margin-left:auto;white-space:nowrap;transition:all .15s}
.togall:hover{color:#fff;background:#1e1e1e;border-color:#444}
.pnl{background:#151515;border:1px solid #1e1e1e;border-radius:10px;margin-bottom:20px;overflow:hidden}
.ph{display:flex;align-items:center;gap:12px;padding:18px 24px;cursor:pointer;user-select:none;transition:background .1s}
.ph:hover{background:#1a1a1a}
.ph h2{font-size:16px;font-weight:600;color:#fff}
.ph .nm{font-family:'Geist Mono',monospace;font-size:13px;font-weight:500;color:#666;background:#1e1e1e;padding:3px 10px;border-radius:20px}
.ph .nm.al{color:#e74c3c;background:rgba(231,76,60,.1)}
.ph .tg{margin-left:auto;font-size:18px;color:#444;transition:transform .2s;line-height:1}
.ph.x .tg{transform:rotate(-90deg)}
.pb{border-top:1px solid #1e1e1e}.ph.x+.pb{display:none}
.fd{display:flex;gap:16px;padding:18px 24px;border-bottom:1px solid #1a1a1a;align-items:flex-start}.fd:last-child{border:0}
.sv2{font-family:'Geist Mono',monospace;font-size:11px;font-weight:600;text-transform:uppercase;padding:4px 10px;border-radius:4px;flex-shrink:0;letter-spacing:.04em}
.sv2-h{background:rgba(231,76,60,.12);color:#e74c3c;border:1px solid rgba(231,76,60,.2)}
.sv2-m{background:rgba(241,196,15,.08);color:#f1c40f;border:1px solid rgba(241,196,15,.15)}
.ft2{font-size:15px;font-weight:600;color:#eee;margin-bottom:4px}
.fd2{font-size:14px;color:#888;line-height:1.6}
.fd2 code{font-family:'Geist Mono',monospace;background:#1e1e1e;padding:2px 7px;border-radius:3px;font-size:13px;color:#e74c3c}
.kv{display:grid;grid-template-columns:200px 1fr;padding:8px 24px}
.kv dt{font-size:14px;color:#666;padding:12px 0;border-bottom:1px solid #1a1a1a;font-weight:500}
.kv dd{font-family:'Geist Mono',monospace;font-size:14px;color:#ccc;padding:12px 0;border-bottom:1px solid #1a1a1a}
table{width:100%;border-collapse:collapse}
thead th{font-size:12px;font-weight:600;color:#555;text-transform:uppercase;letter-spacing:.05em;text-align:left;padding:14px 18px;border-bottom:1px solid #222;background:#161616;position:sticky;top:48px;white-space:nowrap}
tbody td{padding:13px 18px;border-bottom:1px solid #1a1a1a;font-size:14px;color:#bbb;vertical-align:top;line-height:1.55}
tbody tr:nth-child(even) td{background:rgba(255,255,255,.01)}
tbody tr:hover td{background:rgba(192,57,43,.06)}
td.m{font-family:'Geist Mono',monospace;font-size:13px}
td.wr{max-width:340px;word-break:break-all}
.b{display:inline-block;font-family:'Geist Mono',monospace;font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px;letter-spacing:.02em}
.b-on{color:#27ae60;background:rgba(39,174,96,.1);border:1px solid rgba(39,174,96,.2)}
.b-off{color:#555;background:#1a1a1a;border:1px solid #252525}
.b-crit{color:#e74c3c;background:rgba(231,76,60,.1);border:1px solid rgba(231,76,60,.2)}
.b-warn{color:#f39c12;background:rgba(243,156,18,.08);border:1px solid rgba(243,156,18,.15)}
.b-muted{color:#777;background:#1a1a1a;border:1px solid #2a2a2a}
.tb{display:flex;gap:10px;padding:12px 18px;align-items:center;background:#161616;border-bottom:1px solid #1e1e1e}
.tb input{background:#1a1a1a;border:1px solid #2a2a2a;color:#ccc;padding:8px 12px;font-family:inherit;font-size:13px;width:240px;outline:0;border-radius:5px}
.tb input:focus{border-color:#c0392b}.tb input::placeholder{color:#444}
.tb .ct{font-family:'Geist Mono',monospace;font-size:12px;color:#555}
.cp{font-family:'Geist Mono',monospace;font-size:12px;font-weight:500;color:#888;background:#1a1a1a;border:1px solid #2a2a2a;padding:7px 14px;cursor:pointer;border-radius:5px;margin-left:auto;transition:all .15s;white-space:nowrap}
.cp:hover{color:#c0392b;border-color:#c0392b}.cp.ok{color:#27ae60;border-color:#27ae60}
.sub{padding:10px 18px;font-size:12px;color:#444}
@media(max-width:900px){.page{padding:20px 16px 60px}.summary{grid-template-columns:repeat(3,1fr)}.kv{grid-template-columns:1fr}.top{flex-direction:column;align-items:flex-start}td{padding:10px 12px;font-size:13px}.tb input{width:100%}.tb{flex-wrap:wrap}.sv{font-size:24px}}
@media(max-width:500px){.summary{grid-template-columns:repeat(2,1fr)}.pills{gap:4px}.pills a{padding:5px 10px;font-size:11px}}
</style></head><body>
<div class="page" id="root"></div>
<script>
var D=JSON.parse(atob("$jsonB64"));

function e(s){return s!=null?String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'):''}
function bg(t,c){return t?'<span class="b b-'+c+'">'+e(t)+'</span>':''}

function build(){
var si=D.SystemInfo||{},dc=D.DomainContext||{},F=D.Findings||[],M=D.Meta||{};
var du=D.DomainUsers||[],pa=D.PrivilegedAccounts||[],co=D.Computers||[];
var gr=D.Groups||[],pp=D.PasswordPolicy||{},gp=D.GPOs||[];
var kb=D.Kerberoastable||[],ud=D.UnconstrainedDelegation||[],cd=D.ConstrainedDelegation||[];
var cn=D.Connections||[],sh=D.Shares||[],dn=D.DNS||[],tk=D.ScheduledTasks||[];
var sd=D.SensitiveDescriptions||[],ia=D.InactiveAccounts||[],se=D.Security||{};
var gpp=D.GPPPasswords||[],maq=D.MachineAccountQuota,laps=D.LAPS||[];
var uniq=[];pa.forEach(function(a){if(uniq.indexOf(a.member)<0)uniq.push(a.member)});
var o='';

o+='<div class="top"><div class="top-left"><div class="logo"><svg viewBox="0 0 24 24"><path d="M12 2L2 7v10l10 5 10-5V7L12 2zm0 2.18L19.18 7 12 10.82 4.82 7 12 4.18zM4 8.62l7 3.5V19.5l-7-3.5V8.62zm16 0v7.38l-7 3.5v-7.38l7-3.5z"/></svg></div>';
o+='<div class="top-title">ADEnum<span>.</span>'+e(si.domain)+'</div></div>';
o+='<div class="top-meta"><b>'+e(si.hostname)+'</b> &middot; '+e(si.user)+'<br>'+e(M.timestamp)+'</div></div>';

o+='<div class="summary">';
o+='<div class="sc"><div class="sv">'+du.length+'</div><div class="sl">users</div></div>';
o+='<div class="sc"><div class="sv">'+co.length+'</div><div class="sl">machines</div></div>';
o+='<div class="sc"><div class="sv crit">'+uniq.length+'</div><div class="sl">privileged</div></div>';
o+='<div class="sc"><div class="sv crit">'+F.length+'</div><div class="sl">findings</div></div>';
o+='<div class="sc"><div class="sv">'+ia.length+'</div><div class="sl">inactive</div></div>';
o+='<div class="sc"><div class="sv'+(sd.length?' crit':' safe')+'">'+sd.length+'</div><div class="sl">leaked creds</div></div>';
o+='</div>';

o+='<div class="pills">';
var tabs=['findings','system','users','admins','computers','groups','policy','gpos','kerberoast','delegation','connections','shares','dns','tasks'];
if(cd.length>0)tabs.splice(tabs.indexOf('delegation')+1,0,'constrained');
if(se.avProducts||se.securityServices)tabs.push('security');
tabs.forEach(function(n){o+='<a href="#'+n+'" onclick="openSec(\''+n+'\')">'+n+'</a>'});
o+='<button class="togall" id="togAll" onclick="toggleAll()">Expand all</button></div>';

// FINDINGS (open by default)
o+=po('findings','Findings',F.length,false,true);
F.forEach(function(f){o+='<div class="fd"><div class="sv2 '+(f.severity==='high'?'sv2-h':'sv2-m')+'">'+f.severity+'</div><div><div class="ft2">'+e(f.title)+'</div><div class="fd2">'+e(f.detail)+'</div></div></div>'});
o+=pc();

// SYSTEM
o+=po('system','System Information','',true);
o+='<dl class="kv">';
[['Hostname',si.hostname],['User',si.user],['OS',si.os],['Build',si.version],['Domain',si.domain],['Forest',dc.forest],['Functional level',dc.domainMode],['PDC',dc.pdc],['Schema Master',dc.schema],['RID Master',dc.rid],['Infra Master',dc.infra],['Admin session',si.isAdmin?'<span style="color:#e74c3c;font-weight:600">Yes</span>':'No'],['MAQ',maq!=null?maq:'—'],['Last boot',si.lastBoot],['PowerShell',si.psVersion]].forEach(function(r){o+='<dt>'+r[0]+'</dt><dd>'+(r[1]!=null?r[1]:'—')+'</dd>'});
o+='</dl>'+pc();

// USERS
o+=po('users','Domain Users',du.length,true);
o+=tb('ut','Copy usernames');
o+='<table id="ut"><thead><tr><th>Account</th><th>Display name</th><th>Status</th><th>Privilege</th><th>Member of</th><th>Last logon</th><th>Pwd set</th><th>Description</th></tr></thead><tbody>';
du.forEach(function(u){var priv='';if(u.adminCount==1){var g=u.memberOf||'';if(/Domain Admins/.test(g))priv+='DA ';if(/Enterprise Admins/.test(g))priv+='EA ';if(/Schema Admins/.test(g))priv+='SA ';if(/^Administrators|; Administrators/.test(g))priv+='Admin ';priv=priv.trim()||'Priv'}
  var ll=u.lastLogon||'Never';var w=ll==='Never'&&u.enabled;
  o+='<tr><td class="m">'+e(u.sam)+'</td><td>'+e(u.displayName)+'</td><td>'+(u.enabled?bg('Enabled','on'):bg('Disabled','off'))+'</td><td>'+(priv?bg(priv,'crit'):'')+'</td><td class="wr" style="font-size:13px;color:#777">'+e(u.memberOf)+'</td><td class="m"'+(w?' style="color:#f39c12"':'')+'>'+e(ll)+'</td><td class="m">'+e(u.pwdLastSet)+'</td><td class="wr">'+e(u.description)+'</td></tr>'});
o+='</tbody></table>'+pc();

// ADMINS
o+=po('admins','Privileged Accounts',pa.length+' memberships',true);
o+='<div class="tb"><span class="ct" style="color:#999">Unique: <b style="color:#eee">'+uniq.join(', ')+'</b></span><button class="cp" onclick="cpy(this,\'at\',1)">Copy members</button></div>';
o+='<table id="at"><thead><tr><th>Group</th><th>Member</th><th>DN</th></tr></thead><tbody>';
pa.forEach(function(a){var c=/Domain Admins|Enterprise Admins|Schema Admins/.test(a.group)?'crit':'warn';o+='<tr><td>'+bg(a.group,c)+'</td><td class="m">'+e(a.member)+'</td><td class="wr m" style="color:#555">'+e(a.dn)+'</td></tr>'});
o+='</tbody></table>'+pc();

// COMPUTERS
o+=po('computers','Domain Computers',co.length,true);
o+=tb('ct','Copy hostnames');
o+='<table id="ct"><thead><tr><th>Hostname</th><th>FQDN</th><th>OS</th><th>Status</th><th>Last logon</th><th>OU</th></tr></thead><tbody>';
co.forEach(function(c){o+='<tr><td class="m">'+e(c.name)+'</td><td class="m">'+e(c.fqdn)+'</td><td>'+e(c.os)+'</td><td>'+(c.enabled?bg('Enabled','on'):bg('Disabled','off'))+'</td><td class="m">'+e(c.lastLogon)+'</td><td class="wr" style="color:#666">'+e(c.ou)+'</td></tr>'});
o+='</tbody></table>'+pc();

// GROUPS
var pg=gr.filter(function(g){return g.memberCount>0||g.adminCount==1});
o+=po('groups','Domain Groups',gr.length+' total',true);
o+=tb('grt','');
o+='<table id="grt"><thead><tr><th>Group</th><th>Count</th><th>Priv</th><th>Members</th></tr></thead><tbody>';
pg.forEach(function(g){o+='<tr><td class="m">'+e(g.name)+'</td><td class="m">'+g.memberCount+'</td><td>'+(g.adminCount==1?bg('Yes','crit'):'')+'</td><td class="wr" style="color:#777">'+e(g.members)+'</td></tr>'});
o+='</tbody></table>'+pc();

// POLICY
o+=po('policy','Password Policy',pp.minLength<12||pp.lockoutThreshold===0?'issues':'',true);
o+='<dl class="kv">';
o+='<dt>Min length</dt><dd'+(pp.minLength<12?' style="color:#e74c3c;font-weight:600"':'')+'>'+pp.minLength+(pp.minLength<12?' <span style="color:#555;font-weight:400">&larr; recommended 12+</span>':'')+'</dd>';
o+='<dt>Min age</dt><dd>'+e(pp.minAge)+'</dd><dt>Max age</dt><dd>'+e(pp.maxAge)+'</dd><dt>History</dt><dd>'+pp.history+'</dd>';
o+='<dt>Lockout threshold</dt><dd'+(pp.lockoutThreshold===0?' style="color:#e74c3c;font-weight:600"':'')+'>'+pp.lockoutThreshold+(pp.lockoutThreshold===0?' <span style="color:#555;font-weight:400">&larr; unprotected</span>':'')+'</dd>';
o+='<dt>Lockout duration</dt><dd>'+e(pp.lockoutDuration)+'</dd><dt>Window</dt><dd>'+e(pp.lockoutWindow)+'</dd>';
o+='<dt>Complexity</dt><dd'+(pp.complexityRequired?' style="color:#27ae60"':'')+'>'+pp.complexityRequired+'</dd></dl>'+pc();

// GPOS
o+=po('gpos','GPOs',gp.length,true);
o+='<table><thead><tr><th>Name</th><th>Status</th><th>Changed</th><th>GUID</th></tr></thead><tbody>';
gp.forEach(function(g){o+='<tr><td>'+e(g.name)+'</td><td>'+bg(g.status,'on')+'</td><td class="m">'+e(g.lastChanged)+'</td><td class="m wr" style="color:#555">'+e(g.guid)+'</td></tr>'});
o+='</tbody></table>'+pc();

// KERBEROAST
o+=po('kerberoast','Kerberoastable',kb.length,true);
o+='<table><thead><tr><th>Account</th><th>SPN</th><th>Admin</th><th>Pwd set</th><th>Description</th></tr></thead><tbody>';
kb.forEach(function(k){o+='<tr><td class="m">'+e(k.sam)+'</td><td class="m">'+e(k.spns)+'</td><td>'+(k.adminCount==1?bg('Yes','muted'):'')+'</td><td class="m">'+e(k.pwdLastSet)+'</td><td class="wr">'+e(k.description)+'</td></tr>'});
o+='</tbody></table>'+pc();

// UNCONSTRAINED DELEGATION
o+=po('delegation','Unconstrained Delegation',ud.length,true);
o+='<table><thead><tr><th>Type</th><th>Identity</th><th>FQDN</th><th>OS</th></tr></thead><tbody>';
ud.forEach(function(u){o+='<tr><td>'+bg(u.type,'muted')+'</td><td class="m">'+e(u.identity)+'</td><td class="m">'+e(u.fqdn)+'</td><td>'+e(u.os)+'</td></tr>'});
o+='</tbody></table>'+pc();

// CONSTRAINED DELEGATION
if(cd.length>0){o+=po('constrained','Constrained Delegation',cd.length,true);
  o+='<table><thead><tr><th>Identity</th><th>Protocol</th><th>Targets</th></tr></thead><tbody>';
  cd.forEach(function(c){o+='<tr><td class="m">'+e(c.identity)+'</td><td>'+bg(c.protocol,c.protocol.indexOf('Any')>-1?'warn':'muted')+'</td><td class="wr m">'+e(c.targets)+'</td></tr>'});
  o+='</tbody></table>'+pc();}

// CONNECTIONS
var ext=cn.filter(function(c){return c.remoteAddr!=='::1'&&!/^fe80/.test(c.remoteAddr)&&c.remoteAddr!=='127.0.0.1'});
o+=po('connections','Connections',cn.length+' total',true);
o+=tb('nt','Copy remote IPs');
o+='<table id="nt"><thead><tr><th>Local</th><th>Remote</th><th>Process</th><th>PID</th></tr></thead><tbody>';
ext.forEach(function(c){var pub=!/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(c.remoteAddr);o+='<tr><td class="m">'+e(c.localAddr)+':'+c.localPort+'</td><td class="m"'+(pub?' style="color:#e74c3c"':'')+'>'+e(c.remoteAddr)+':'+c.remotePort+'</td><td>'+e(c.process)+'</td><td class="m">'+c.pid+'</td></tr>'});
o+='</tbody></table>';
if(cn.length>ext.length)o+='<div class="sub">'+(cn.length-ext.length)+' loopback connections hidden</div>';
o+=pc();

// SHARES
o+=po('shares','Shares',sh.length,true);
o+='<table><thead><tr><th>Name</th><th>Path</th><th>Description</th><th>Type</th></tr></thead><tbody>';
sh.forEach(function(s){var a=s.type>2e9;o+='<tr><td class="m">'+e(s.name)+'</td><td class="m wr">'+e(s.path)+'</td><td>'+e(s.description)+'</td><td>'+(a?bg('Admin$','warn'):bg('Share','muted'))+'</td></tr>'});
o+='</tbody></table>'+pc();

// DNS
o+=po('dns','DNS Records',dn.length,true);
o+=tb('dt','Copy names');
o+='<table id="dt"><thead><tr><th>Record</th><th>DN</th></tr></thead><tbody>';
dn.forEach(function(d){o+='<tr><td class="m">'+e(d.name)+'</td><td class="m wr" style="color:#555">'+e(d.dn)+'</td></tr>'});
o+='</tbody></table>'+pc();

// TASKS
o+=po('tasks','Scheduled Tasks',tk.length,true);
o+='<table><thead><tr><th>Name</th><th>State</th><th>Run as</th><th>Action</th><th>Last run</th></tr></thead><tbody>';
tk.forEach(function(t){o+='<tr><td class="wr">'+e(t.name)+'</td><td>'+bg(t.state==='Running'?'Running':'Ready',t.state==='Running'?'on':'muted')+'</td><td class="m">'+e(t.runAs)+'</td><td class="m wr">'+e(t.action)+'</td><td class="m">'+e(t.lastRun)+'</td></tr>'});
o+='</tbody></table>'+pc();

// SECURITY
var avP=se.avProducts||[],svS=se.securityServices||[],edP=se.securityProcesses||[];
if(avP.length+svS.length+edP.length>0){
  o+=po('security','AV / EDR Detection',avP.length+svS.length+edP.length,true);
  if(avP.length){o+='<table><thead><tr><th>AV Product</th><th>Enabled</th><th>Updated</th></tr></thead><tbody>';avP.forEach(function(a){o+='<tr><td>'+e(a.name)+'</td><td>'+(a.enabled?bg('Yes','on'):bg('No','off'))+'</td><td>'+(a.updated?bg('Yes','on'):bg('No','warn'))+'</td></tr>'});o+='</tbody></table>'}
  if(svS.length){o+='<table><thead><tr><th>Security Service</th><th>Display Name</th><th>Status</th></tr></thead><tbody>';svS.forEach(function(s){o+='<tr><td class="m">'+e(s.name)+'</td><td>'+e(s.displayName)+'</td><td>'+bg(s.status,s.status==='Running'?'on':'off')+'</td></tr>'});o+='</tbody></table>'}
  if(edP.length){o+='<table><thead><tr><th>EDR Process</th><th>PID</th></tr></thead><tbody>';edP.forEach(function(p){o+='<tr><td class="m">'+e(p.name)+'</td><td class="m">'+p.pid+'</td></tr>'});o+='</tbody></table>'}
  o+=pc();}

o+='<div style="text-align:center;padding:32px 0 0;opacity:.35;font-size:13px">ADEnum v1.0 &middot; '+e(si.domain)+' &middot; '+e(M.timestamp)+'</div>';
document.getElementById('root').innerHTML=o}

function po(id,t,n,shut,alert){return '<div class="pnl" id="'+id+'"><div class="ph'+(shut?' x':'')+'" onclick="tog(this)"><h2>'+t+'</h2>'+(n!==''&&n!=null?'<span class="nm'+(alert?' al':'')+'">'+n+'</span>':'')+'<span class="tg">&#9662;</span></div><div class="pb"'+(shut?' style="display:none"':'')+'>';}
function pc(){return '</div></div>';}
function tb(id,cp){var o='<div class="tb"><input type="text" placeholder="Type to filter..." oninput="flt(this,\''+id+'\')"><span class="ct" id="'+id+'-c"></span>';if(cp)o+='<button class="cp" onclick="cpy(this,\''+id+'\',0)">'+cp+'</button>';return o+'</div>';}
function tog(el){el.classList.toggle('x');var b=el.nextElementSibling;if(b)b.style.display=b.style.display==='none'?'':'none';updBtn();}
function toggleAll(){var p=document.querySelectorAll('.ph'),any=false;p.forEach(function(h){if(h.classList.contains('x'))any=true});p.forEach(function(h){var b=h.nextElementSibling;if(any){h.classList.remove('x');if(b)b.style.display=''}else{h.classList.add('x');if(b)b.style.display='none'}});updBtn();}
function updBtn(){var b=document.getElementById('togAll');if(!b)return;var any=false;document.querySelectorAll('.ph').forEach(function(h){if(h.classList.contains('x'))any=true});b.textContent=any?'Expand all':'Collapse all';}
function openSec(id){var p=document.getElementById(id);if(!p)return;var h=p.querySelector('.ph'),b=p.querySelector('.pb');if(h&&h.classList.contains('x')){h.classList.remove('x');if(b)b.style.display='';updBtn();}}
function flt(inp,id){var t=document.getElementById(id);if(!t)return;var q=inp.value.toLowerCase(),rows=t.querySelectorAll('tbody tr'),v=0;rows.forEach(function(r){var ok=r.textContent.toLowerCase().indexOf(q)>-1;r.style.display=ok?'':'none';if(ok)v++});var c=document.getElementById(id+'-c');if(c)c.textContent=q?v+'/'+rows.length:'';}
function cpy(btn,id,col){var t=document.getElementById(id);if(!t)return;var rows=t.querySelectorAll('tbody tr'),vals=[],seen={};rows.forEach(function(r){if(r.style.display==='none')return;var c=r.querySelectorAll('td');if(c[col]){var v=c[col].textContent.trim();if(v&&v!=='Never'&&!seen[v]){seen[v]=1;vals.push(v)}}});if(navigator.clipboard){navigator.clipboard.writeText(vals.join('\n')).then(function(){var orig=btn.textContent;btn.textContent='Copied!';btn.classList.add('ok');setTimeout(function(){btn.textContent=orig;btn.classList.remove('ok')},1500)})}}

build();
</script></body></html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "  [+] HTML: $htmlPath" -ForegroundColor Green
}

#endregion

#region ==================== MAIN ====================

function Invoke-FullEnum {
    param(
        [switch]$SkipDomain,
        [switch]$ScanAllShares
    )

    Initialize-ADEnum
    Write-Host $Script:Banner -ForegroundColor Cyan
    Write-Host ""
    $startTime = Get-Date

    $null = Get-SystemInfo
    $null = Get-LocalUsersEnum
    $null = Get-LocalAdmins

    $dj=$false;try{$dj=(Get-CimInstance Win32_ComputerSystem).PartOfDomain}catch{}

    if (-not $SkipDomain -and $dj) {
        $null = Get-DomainContext
        $allUsers = Get-DomainUsersLDAP
        $Script:Report.DomainUsers = $allUsers
        $null = Get-DomainAdmins
        $null = Get-SensitiveDescriptions
        $null = Get-InactiveAccounts
        $null = Get-NeverExpirePasswords
        $null = Get-KerberoastableAccounts
        $null = Get-ASREPRoastableAccounts
        $null = Get-DomainComputers
        $null = Get-DomainControllers
        $null = Get-DomainGroupsEnum
        $null = Get-OUStructure
        $null = Get-PasswordPolicy
        $null = Get-GPOInfo
        $null = Get-DomainTrusts
        $null = Get-DNSRecords
        $null = Get-UnconstrainedDelegation
        $null = Get-ConstrainedDelegation
        $null = Get-MachineAccountQuota
        $null = Get-LAPSStatus
        $null = Get-GPPPasswords
    } else {
        Write-Host "`n  [skip] not domain-joined or -SkipDomain" -ForegroundColor Yellow
    }

    $null = Get-NetworkShares
    if ($ScanAllShares -and $Script:Report.Computers) {
        foreach ($comp in $Script:Report.Computers) {
            if ($comp.name -ne $env:COMPUTERNAME) {
                Write-Status "shares" "scanning $($comp.name)..." "White"
                try { $remoteShares = @(Get-CimInstance -ClassName Win32_Share -ComputerName $comp.fqdn -ErrorAction Stop | ForEach-Object {[ordered]@{name=$_.Name;path=$_.Path;description=$_.Description;type=$_.Type;host=$comp.name}})
                    $Script:Report.Shares += $remoteShares
                } catch { Write-Status "shares" "$($comp.name): access denied or offline" "Yellow" }
            }
        }
    }
    $null = Get-NetConnections
    $null = Get-InterestingServices
    $null = Get-ScheduledTasksEnum
    $null = Get-AVStatus

    Write-Host "`n  ========================================" -ForegroundColor DarkGray
    $null = Export-JSON
    $null = Export-HTMLReport

    $elapsed = (Get-Date) - $startTime
    $hi=@($Script:Findings|Where-Object{$_.severity -eq 'high'}).Count
    $md=@($Script:Findings|Where-Object{$_.severity -eq 'medium'}).Count
    Write-Host ""
    Write-Host "  completed in $($elapsed.ToString('mm\:ss'))" -ForegroundColor Cyan
    Write-Host "  findings: $($Script:Findings.Count) ($hi high, $md medium)" -ForegroundColor $(if($hi -gt 0){'Red'}elseif($md -gt 0){'Yellow'}else{'Green'})
    Write-Host ""
}

function Get-ADEnumHelp {
    Write-Host $Script:Banner -ForegroundColor Cyan
    Write-Host @"

  Invoke-FullEnum                 run everything, export JSON + HTML
  Invoke-FullEnum -SkipDomain     skip AD enumeration
  Invoke-FullEnum -ScanAllShares  enumerate shares on all domain machines

  individual functions:
    Get-SystemInfo              Get-DomainContext
    Get-LocalUsersEnum          Get-LocalAdmins
    Get-DomainUsersLDAP         Get-DomainAdmins
    Get-SensitiveDescriptions   Get-InactiveAccounts
    Get-NeverExpirePasswords    Get-KerberoastableAccounts
    Get-ASREPRoastableAccounts  Get-DomainComputers
    Get-DomainControllers       Get-DomainGroupsEnum
    Get-OUStructure             Get-PasswordPolicy
    Get-GPOInfo                 Get-DomainTrusts
    Get-DNSRecords              Get-UnconstrainedDelegation
    Get-ConstrainedDelegation   Get-MachineAccountQuota
    Get-LAPSStatus              Get-GPPPasswords
    Get-AVStatus                Get-NetworkShares
    Get-NetConnections          Get-InterestingServices
    Get-ScheduledTasksEnum

"@ -ForegroundColor White
}

#endregion

Write-Host "[+] ADEnum v1.0 loaded. Run 'Invoke-FullEnum' or 'Get-ADEnumHelp'" -ForegroundColor Green