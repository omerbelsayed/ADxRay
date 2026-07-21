<#
.SYNOPSIS
Generates synthetic ADxRay "Hammer" inventory files so the real ADxRay.ps1 Report
function can be exercised end-to-end without a live Active Directory environment.

.DESCRIPTION
This is a demo/test data generator only - it is not part of the ADxRay assessment
engine and performs no Active Directory activity of any kind. It fabricates the
same Export-Clixml files that ADxRay.ps1's Hammer phase produces under
C:\ADxRay\Hammer, using a mix of "healthy" and "unhealthy" values so the resulting
HTML report shows the report's real green/yellow/red logic in action - including
the new Kerberos/Identity/LDAP security checks.

After running this script, generate the report itself with:
    .\ADxRay.ps1     (choose option 6 - "Process Collected Inventory Files")
#>

$HammerPath = 'C:\ADxRay\Hammer'
if (-not (Test-Path $HammerPath)) { New-Item -ItemType Directory -Force -Path $HammerPath | Out-Null }
Get-ChildItem -Path $HammerPath -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

$Now = Get-Date

#region Helper: replicate ADxRay's own UAC-bit extraction so downstream report parsing matches exactly
function New-UacBitGroups
{
    param([int[]]$UacValues)

    $att = @()
    foreach ($UAC in $UacValues)
    {
        $att += 1..26 | Where-Object { $UAC -band [math]::Pow(2, $_) }
    }
    return $att | Group-Object
}
#endregion

#region ---------------------------------------------------------- Forest.xml ----------------------------------------------------------

$ForestName    = 'contoso.com'
$DomainNames   = @('contoso.com', 'child.contoso.com')

$Fores = @{
    'ForestName'         = $ForestName
    'Domains'            = $DomainNames
    'RecycleBin'         = 'Enabled'
    'ForestMode'         = [PSCustomObject]@{ Value = 'Windows2016Forest' }
    'GlobalCatalogs'     = @('DC01.contoso.com', 'DC03.child.contoso.com')
    'Sites'              = @('Default-First-Site-Name', 'Branch-Office-EU')
    'Trusts'             = @()
    'SPN'                = 'found 0 group of duplicate SPNs.'
    'DuplicatedDNSZones' = @()
}

$Fores | Export-Clixml -Path (Join-Path $HammerPath 'Forest.xml')

#endregion

#region ------------------------------------------------------- Domain_*.xml -----------------------------------------------------------

function New-DemoDomainFile
{
    param(
        [string]$DomainName,
        [string]$ParentDomain,
        [string[]]$ChildDomains,
        [int]$DcCount,
        [int[]]$UserUacValues,
        [int]$WorkstationCount,
        [int]$WorkstationUnsupportedCount,
        [int]$ServerCount,
        [int]$ServerUnsupportedCount,
        [int]$ProtectedUsersMembers,
        [int]$KerberoastableCount,
        [int]$KerberoastableOldPwdOfThose,
        [int]$KerberoastableRC4OfThose,
        [int]$AdminSDHolderOrphanCount,
        [int]$UnconstrainedDelegationComputerCount,
        [double]$KrbtgtAgeDays,
        [int]$SpnDuplicateGroups
    )

    # ---- Users (real UAC bitmask extraction, matches ADxRay's own parsing) ----
    $UsersGrouped = New-UacBitGroups -UacValues $UserUacValues

    # ---- Computers (mimics dsquery '<DN> <OperatingSystem>' line-per-object output; index 0 is discarded by the report) ----
    $Computers = @('"header placeholder"')
    for ($i = 1; $i -le $WorkstationCount; $i++)
    {
        $os = if ($i -le $WorkstationUnsupportedCount) { 'Windows 7 Professional' } else { 'Windows 11 Enterprise' }
        $Computers += "`"CN=WKS$('{0:D3}' -f $i),OU=Workstations,DC=$($DomainName.Replace('.', ',DC='))`" `"$os`""
    }
    for ($i = 1; $i -le $ServerCount; $i++)
    {
        $os = if ($i -le $ServerUnsupportedCount) { 'Windows Server 2008 R2 Standard' } else { 'Windows Server 2022 Standard' }
        $Computers += "`"CN=SRV$('{0:D3}' -f $i),OU=Servers,DC=$($DomainName.Replace('.', ',DC='))`" `"$os`""
    }

    # ---- SysVol content summary ----
    $SysVolContent = @(
        [PSCustomObject]@{ Extension = '.pol'; Count = 42;  'TotalSize (MB)' = '1.20'; TotalSize = 1258291 }
        [PSCustomObject]@{ Extension = '.inf'; Count = 30;  'TotalSize (MB)' = '0.45'; TotalSize = 471859 }
        [PSCustomObject]@{ Extension = '.xml'; Count = 18;  'TotalSize (MB)' = '0.30'; TotalSize = 314572 }
    )

    # ---- Admin / Tier 0 groups (membership counts) ----
    $AdminGroups = @{
        'Domain Admins'                   = 4
        'Schema Admins'                   = 0
        'Enterprise Admins'               = 0
        'Server Operators'                = 0
        'Account Operators'               = 2
        'Administrators'                  = 5
        'Backup Operators'                = 1
        'Print Operators'                 = 0
        'Domain Controllers'              = $DcCount
        'Read-only Domain Controllers'    = 0
        'Group Policy Creator Owners'     = 1
        'Cryptographic Operators'         = 0
        'Distributed COM Users'           = 0
        'Protected Users'                 = $ProtectedUsersMembers
    }

    $Groups = @(
        [PSCustomObject]@{ Name = 'Domain Users'; Count = ($UserUacValues.Count) }
        [PSCustomObject]@{ Name = 'All Employees'; Count = [math]::Floor($UserUacValues.Count * 0.8) }
    )

    # ---- Kerberoastable accounts (with password age + supported encryption types) ----
    $Kerberoastable = @()
    for ($i = 1; $i -le $KerberoastableCount; $i++)
    {
        $isOld = $i -le $KerberoastableOldPwdOfThose
        $isRc4 = $i -le $KerberoastableRC4OfThose
        $Kerberoastable += [PSCustomObject]@{
            SamAccountName            = "svc-app$i"
            PasswordLastSet           = if ($isOld) { $Now.AddDays(-540) } else { $Now.AddDays(-60) }
            ServicePrincipalName      = @("HTTP/app$i.$DomainName")
            SupportedEncryptionTypes  = if ($isRc4) { $null } else { 24 }   # 24 = AES128 (8) + AES256 (16), no RC4 bit (4)
        }
    }

    # ---- AdminSDHolder orphans ----
    $AdminSDHolderOrphans = @()
    for ($i = 1; $i -le $AdminSDHolderOrphanCount; $i++)
    {
        $AdminSDHolderOrphans += [PSCustomObject]@{ SamAccountName = "former-admin$i"; MemberOf = @() }
    }

    # ---- Unconstrained delegation computers ----
    $UnconstrainedDelegationComputers = @()
    for ($i = 1; $i -le $UnconstrainedDelegationComputerCount; $i++)
    {
        $UnconstrainedDelegationComputers += [PSCustomObject]@{ SamAccountName = "LEGACYAPP$('{0:D2}' -f $i)$" }
    }

    $DomainTable = @{
        'Domain'                            = $DomainName
        'DNSRoot'                           = $DomainName
        'ParentDomain'                      = $ParentDomain
        'ChildDomains'                      = $ChildDomains
        'DomainMode'                        = [PSCustomObject]@{ Value = 'Windows2016Domain' }
        'ComputersContainer'                = "CN=Computers,DC=$($DomainName.Replace('.', ',DC='))"
        'UsersContainer'                    = "CN=Users,DC=$($DomainName.Replace('.', ',DC='))"
        'DCCount'                           = $DcCount
        'SysVolContent'                     = $SysVolContent
        'Users'                             = $UsersGrouped
        'RODC'                              = @()
        'Computers'                         = $Computers
        'AdminGroups'                       = $AdminGroups
        'Groups'                            = $Groups
        'SmallGroups'                       = 3
        'Kerberoastable'                    = $Kerberoastable
        'AdminSDHolderOrphans'              = $AdminSDHolderOrphans
        'UnconstrainedDelegationComputers'  = $UnconstrainedDelegationComputers
        'KrbtgtPasswordLastSet'             = $Now.AddDays(-1 * $KrbtgtAgeDays)
    }

    $DomainTable | Export-Clixml -Path (Join-Path $HammerPath "Domain_$DomainName.xml")
}

# --- contoso.com : the "messier" root domain, deliberately mixed good/bad findings ---
$ContosoUac = @()
$ContosoUac += ,512  * 480                  # normal enabled users
$ContosoUac += ,514  * 15                   # disabled
$ContosoUac += ,66048 * 3                   # password never expires (512+65536)
$ContosoUac += ,640  * 2                    # reversible encryption (512+128)
$ContosoUac += ,2097664 * 1                 # DES only (512+2097152)
$ContosoUac += ,4194816 * 2                 # AS-REP roastable (512+4194304)
$ContosoUac += ,524800 * 1                  # unconstrained delegation user (512+524288)

New-DemoDomainFile -DomainName 'contoso.com' -ParentDomain '' -ChildDomains @('child.contoso.com') `
    -DcCount 2 -UserUacValues $ContosoUac `
    -WorkstationCount 220 -WorkstationUnsupportedCount 6 `
    -ServerCount 40 -ServerUnsupportedCount 2 `
    -ProtectedUsersMembers 0 `
    -KerberoastableCount 5 -KerberoastableOldPwdOfThose 2 -KerberoastableRC4OfThose 3 `
    -AdminSDHolderOrphanCount 2 `
    -UnconstrainedDelegationComputerCount 1 `
    -KrbtgtAgeDays 402 `
    -SpnDuplicateGroups 0

# --- child.contoso.com : the "clean" child domain, mostly green ---
$ChildUac = @()
$ChildUac += ,512 * 78
$ChildUac += ,514 * 5

New-DemoDomainFile -DomainName 'child.contoso.com' -ParentDomain 'contoso.com' -ChildDomains @() `
    -DcCount 1 -UserUacValues $ChildUac `
    -WorkstationCount 60 -WorkstationUnsupportedCount 0 `
    -ServerCount 8 -ServerUnsupportedCount 0 `
    -ProtectedUsersMembers 3 `
    -KerberoastableCount 0 -KerberoastableOldPwdOfThose 0 -KerberoastableRC4OfThose 0 `
    -AdminSDHolderOrphanCount 0 `
    -UnconstrainedDelegationComputerCount 0 `
    -KrbtgtAgeDays 45 `
    -SpnDuplicateGroups 0

#endregion

#region --------------------------------------------------------- Inv_*.xml ------------------------------------------------------------

function New-DcDiagText
{
    param([string]$DcShortName, [string[]]$FailingTests = @())

    $tests = 'Connectivity','Advertising','FrsEvent','DFSREvent','SysVolCheck','KccEvent','KnowsOfRoleHolders','MachineAccount','NCSecDesc','NetLogons','ObjectsReplicated','Replications','RidManager','Services','SystemLog','VerifyReferences'

    $lines = @("Directory Server Diagnosis", "Performing initial setup:", "   Doing initial required tests", "   Testing server: Default-First-Site-Name\$DcShortName")
    foreach ($t in $tests)
    {
        $lines += "      Starting test: $t"
        if ($t -in $FailingTests)
        {
            $lines += "         An error has occurred."
            $lines += "         ......................... $DcShortName failed test $t"
        }
        else
        {
            $lines += "         ......................... $DcShortName passed test $t"
        }
    }
    return $lines
}

function New-DemoDcFile
{
    param(
        [string]$DcFqdn,
        [string]$DomainName,
        [bool]$IsGC,
        [string]$Roles,
        [string]$Site,
        [int]$LdapServerIntegrity,
        [int]$LdapEnforceChannelBinding,
        [string[]]$FailingDiagTests = @()
    )

    $DcShort = $DcFqdn.Split('.')[0]

    $NTPStatus = @(
        'Leap Indicator: 0(no warning)',
        'Stratum: 3 (secondary reference - syncd by (S)NTP)',
        'Precision: -23 (119.209ns per tick)',
        'Root Delay: 0.0170000s',
        'Root Dispersion: 7.8195400s',
        "Last Successful Sync Time: $((Get-Date).AddHours(-2).ToString('M/d/yyyy h:mm:ss tt'))",
        "Source: $DcFqdn",
        'Poll Interval: 10 (1024s)'
    )
    $NTPConf = @('[Configuration]', 'Type: NT5DS', 'MinPollInterval: 6 (64s)', 'MaxPollInterval: 10 (1024s)')

    $DNS = [PSCustomObject]@{
        ServerSetting     = [PSCustomObject]@{ BindSecondaries = $false }
        ServerScavenging  = [PSCustomObject]@{ ScavengingState = $true }
        ServerRecursion   = [PSCustomObject]@{ Enable = $true }
        ServerZoneAging   = @([PSCustomObject]@{ AgingEnabled = $true })
        ServerForwarder   = [PSCustomObject]@{ IPAddress = @('8.8.8.8', '1.1.1.1') }
        ServerRootHint    = [PSCustomObject]@{
            NameServer = @([PSCustomObject]@{ RecordData = [PSCustomObject]@{ NameServer = 'a.root-servers.net.' } })
        }
    }

    $ldapRR = [PSCustomObject]@{ RecordData = [PSCustomObject]@{ DomainName = @("$DcShort.") } }

    $Backup = @(
        'Backups (Backup, DSA Sig, Invocation ID):',
        "DC=$($DomainName.Replace('.', ',DC='))",
        "    Last backup set for this partition: $((Get-Date).AddDays(-1).ToString('yyyy-MM-dd')) 03:00:05"
    )

    $HotFix = [PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-20); HotFixID = 'KB5040442' }

    $Spooler = [PSCustomObject]@{ State = 'Stopped'; StartMode = 'Disabled' }

    $LdapSecurity = [PSCustomObject]@{
        LDAPServerIntegrity        = $LdapServerIntegrity
        LdapEnforceChannelBinding  = $LdapEnforceChannelBinding
    }

    $FreeSpace = @(
        [PSCustomObject]@{ InstanceName = 'c:'; CookedValue = 63.4 }
        [PSCustomObject]@{ InstanceName = 'd:'; CookedValue = 88.1 }
    )

    $Software64 = @(
        [PSCustomObject]@{ DisplayName = 'Microsoft SQL Server 2019 Native Client'; DisplayVersion = '15.0.4153.1'; Publisher = 'Microsoft Corporation' }
        [PSCustomObject]@{ DisplayName = '7-Zip 23.01'; DisplayVersion = '23.01'; Publisher = 'Igor Pavlov' }
    )
    $Software86 = @(
        [PSCustomObject]@{ DisplayName = 'Notepad++ (32-bit x86)'; DisplayVersion = '8.6.2'; Publisher = 'Notepad++ Team' }
    )

    $DomControl = @{
        'Domain'                  = $DomainName
        'Hostname'                = $DcFqdn
        'IPv4Address'             = '10.10.10.' + (Get-Random -Minimum 10 -Maximum 250)
        'IsGlobalCatalog'         = $IsGC
        'OperatingSystem'         = 'Windows Server 2022 Datacenter'
        'OperatingSystemVersion'  = '10.0 (20348)'
        'OperationMasterRoles'    = $Roles
        'Site'                    = $Site
        'Backup'                  = $Backup
        'HW_Mem'                  = '16,282 MB'
        'HW_Boot'                 = (Get-Date).AddDays(-14).ToString('M/d/yyyy, h:mm:ss tt')
        'HW_Install'              = (Get-Date).AddYears(-2).ToString('M/d/yyyy, h:mm:ss tt')
        'HW_BIOS'                 = "VMware, Inc. VMW71.00.6.0, $((Get-Date).AddYears(-1).ToString('M/d/yyyy'))"
        'HotFix'                  = $HotFix
        'NTPStatus'               = $NTPStatus
        'NTPConf'                 = $NTPConf
        'HW_LogicalProc'          = 4
        'HW_FreeSpace'            = $FreeSpace
        'Spooler_State'           = $Spooler.State
        'Spooler_StartMode'       = $Spooler.StartMode
        'DNS'                     = $DNS
        'ldapRR'                  = $ldapRR
        'DCDiag'                  = New-DcDiagText -DcShortName $DcShort -FailingTests $FailingDiagTests
        'InstalledFeatures'       = [PSCustomObject]@{ EnableSMB1Protocol = $false }
        'InstalledSoftwaresx64'   = $Software64
        'InstalledSoftwaresx86'   = $Software86
        'LdapSecurity'            = $LdapSecurity
    }

    $DomControl | Export-Clixml -Path (Join-Path $HammerPath "Inv_$DcFqdn.xml")
}

# DC01: fully hardened (LDAP signing Required + channel binding Always), clean dcdiag
New-DemoDcFile -DcFqdn 'DC01.contoso.com' -DomainName 'contoso.com' -IsGC $true -Roles 'PDC RID Infrastructure Naming Schema' -Site 'Default-First-Site-Name' `
    -LdapServerIntegrity 2 -LdapEnforceChannelBinding 2

# DC02: weak LDAP config + one failing dcdiag test, to show red/yellow coloring
New-DemoDcFile -DcFqdn 'DC02.contoso.com' -DomainName 'contoso.com' -IsGC $false -Roles '' -Site 'Branch-Office-EU' `
    -LdapServerIntegrity 1 -LdapEnforceChannelBinding 0 -FailingDiagTests @('DFSREvent')

# DC03: clean child-domain DC
New-DemoDcFile -DcFqdn 'DC03.child.contoso.com' -DomainName 'child.contoso.com' -IsGC $true -Roles 'PDC RID Infrastructure' -Site 'Default-First-Site-Name' `
    -LdapServerIntegrity 2 -LdapEnforceChannelBinding 1

#endregion

Write-Host "Demo Hammer data generated at $HammerPath" -ForegroundColor Green
Write-Host "Forest: $ForestName | Domains: $($DomainNames -join ', ') | DCs: DC01.contoso.com, DC02.contoso.com, DC03.child.contoso.com" -ForegroundColor Green
Write-Host "Next: run '.\ADxRay.ps1' and choose option 6 (Process Collected Inventory Files) to render the report." -ForegroundColor Yellow
