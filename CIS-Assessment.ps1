#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Server CIS Hardening Assessment Script with Remediation
.DESCRIPTION
    Evaluates Windows Server against essential CIS benchmark controls and provides remediation guidance
.PARAMETER OutputPath
    Path for HTML report (default: current directory)
.PARAMETER ExportRemediation
    Export PowerShell remediation script for failed checks
.PARAMETER RemediationPath
    Path for remediation script (default: current directory)
.NOTES
    Run as Administrator for complete assessment
    Focuses on critical server hardening controls
#>

param(
    [string]$OutputPath = ".\CIS_Server_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [switch]$ExportRemediation = $false,
    [string]$RemediationPath = "$PSScriptRoot\CIS_Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
)

$results = @()
$remediationSteps = @()
$totalChecks = 50

function Test-RegistryValue {
    param($Path, $Name, $ExpectedValue, $ValueType = "DWord")
    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $value.$Name -eq $ExpectedValue
        }
        return $false
    } catch {
        return $false
    }
}

function Get-RegistryValue {
    param($Path, $Name)
    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $value.$Name
        }
        return $null
    } catch {
        return $null
    }
}

function Add-Result {
    param(
        $Category, 
        $Control, 
        $Description, 
        $Status, 
        $CurrentValue, 
        $ExpectedValue, 
        $Severity = "Medium",
        $RemediationScript = "",
        $RemediationNote = ""
    )
    $script:results += [PSCustomObject]@{
        Category = $Category
        Control = $Control
        Description = $Description
        Status = $Status
        CurrentValue = $CurrentValue
        ExpectedValue = $ExpectedValue
        Severity = $Severity
        RemediationScript = $RemediationScript
        RemediationNote = $RemediationNote
    }
}

function Add-Remediation {
    param(
        $Control,
        $Description,
        $Script,
        $Note,
        $Severity
    )
    if ($Script -ne "") {
        $script:remediationSteps += [PSCustomObject]@{
            Control = $Control
            Description = $Description
            Script = $Script
            Note = $Note
            Severity = $Severity
        }
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Server CIS Hardening Assessment" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
Write-Host "Checking $totalChecks essential server hardening controls..." -ForegroundColor Yellow
Write-Host "This may take a few minutes...`n" -ForegroundColor Yellow

# Export security policy
$secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
$secpolContent = Get-Content "$env:TEMP\secpol.cfg"

# ============================================
# SECTION 1: ACCOUNT POLICIES
# ============================================
Write-Host "[1/10] Checking Account Policies..." -ForegroundColor Green

$minPwdLengthMatch = $secpolContent | Select-String "MinimumPasswordLength"
if ($minPwdLengthMatch) {
    $minPwdLength = $minPwdLengthMatch.Line.Split("=")[1].Trim()
    $minPwdPass = [int]$minPwdLength -ge 14
} else {
    $minPwdLength = "Not configured"
    $minPwdPass = $false
}
Add-Result "Account Policy" "1.1.1" "Minimum Password Length" `
    $(if($minPwdPass){"PASS"}else{"FAIL"}) $minPwdLength "14 or greater" "High" `
    "net accounts /minpwlen:14" `
    "Sets minimum password length to 14 characters. Users will need to create longer passwords on next change."
if (-not $minPwdPass) { Add-Remediation "1.1.1" "Minimum Password Length" "net accounts /minpwlen:14" "Requires users to create passwords of at least 14 characters" "High" }

$pwdComplexityMatch = $secpolContent | Select-String "PasswordComplexity"
if ($pwdComplexityMatch) {
    $pwdComplexity = $pwdComplexityMatch.Line.Split("=")[1].Trim()
    $pwdComplexPass = $pwdComplexity -eq "1"
} else {
    $pwdComplexity = "Not configured"
    $pwdComplexPass = $false
}
Add-Result "Account Policy" "1.1.2" "Password Complexity Enabled" `
    $(if($pwdComplexPass){"PASS"}else{"FAIL"}) $(if($pwdComplexPass){"Enabled"}else{"Disabled"}) "Enabled" "High" `
    "secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\security\templates\secpol.cfg /areas SECURITYPOLICY" `
    "Enable via Local Security Policy > Account Policies > Password Policy > Password must meet complexity requirements"
if (-not $pwdComplexPass) { Add-Remediation "1.1.2" "Password Complexity" "secedit /export /cfg C:\secpol.cfg; (Get-Content C:\secpol.cfg).replace('PasswordComplexity = 0', 'PasswordComplexity = 1') | Out-File C:\secpol.cfg; secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY; Remove-Item -Force C:\secpol.cfg -Confirm:`$false" "Requires uppercase, lowercase, numbers, and special characters" "High" }

$maxPwdAgeMatch = $secpolContent | Select-String "MaximumPasswordAge"
if ($maxPwdAgeMatch) {
    $maxPwdAge = $maxPwdAgeMatch.Line.Split("=")[1].Trim()
    $maxPwdPass = [int]$maxPwdAge -le 70 -and [int]$maxPwdAge -gt 0
} else {
    $maxPwdAge = "Not configured"
    $maxPwdPass = $false
}
Add-Result "Account Policy" "1.1.3" "Maximum Password Age" `
    $(if($maxPwdPass){"PASS"}else{"FAIL"}) "$maxPwdAge days" "70 days or fewer" "Medium" `
    "net accounts /maxpwage:70" `
    "Forces password changes every 70 days"
if (-not $maxPwdPass) { Add-Remediation "1.1.3" "Maximum Password Age" "net accounts /maxpwage:70" "Users must change passwords every 70 days" "Medium" }

$minPwdAgeMatch = $secpolContent | Select-String "MinimumPasswordAge"
if ($minPwdAgeMatch) {
    $minPwdAge = $minPwdAgeMatch.Line.Split("=")[1].Trim()
    $minPwdAgePass = [int]$minPwdAge -ge 1
} else {
    $minPwdAge = "Not configured"
    $minPwdAgePass = $false
}
Add-Result "Account Policy" "1.1.4" "Minimum Password Age" `
    $(if($minPwdAgePass){"PASS"}else{"FAIL"}) "$minPwdAge days" "1 day or more" "Medium" `
    "net accounts /minpwage:1" `
    "Prevents users from immediately changing passwords back"
if (-not $minPwdAgePass) { Add-Remediation "1.1.4" "Minimum Password Age" "net accounts /minpwage:1" "Prevents rapid password changes" "Medium" }

$pwdHistoryMatch = $secpolContent | Select-String "PasswordHistorySize"
if ($pwdHistoryMatch) {
    $pwdHistory = $pwdHistoryMatch.Line.Split("=")[1].Trim()
    $pwdHistoryPass = [int]$pwdHistory -ge 24
} else {
    $pwdHistory = "Not configured"
    $pwdHistoryPass = $false
}
Add-Result "Account Policy" "1.1.5" "Password History" `
    $(if($pwdHistoryPass){"PASS"}else{"FAIL"}) "$pwdHistory passwords" "24 or more" "Medium" `
    "net accounts /uniquepw:24" `
    "Remembers last 24 passwords to prevent reuse"
if (-not $pwdHistoryPass) { Add-Remediation "1.1.5" "Password History" "net accounts /uniquepw:24" "Prevents reusing last 24 passwords" "Medium" }

$lockoutThresholdMatch = $secpolContent | Select-String "LockoutBadCount"
if ($lockoutThresholdMatch) {
    $lockoutThreshold = $lockoutThresholdMatch.Line.Split("=")[1].Trim()
    $lockoutPass = [int]$lockoutThreshold -le 10 -and [int]$lockoutThreshold -gt 0
} else {
    $lockoutThreshold = "Not configured"
    $lockoutPass = $false
}
Add-Result "Account Policy" "1.2.1" "Account Lockout Threshold" `
    $(if($lockoutPass){"PASS"}else{"FAIL"}) "$lockoutThreshold attempts" "10 or fewer" "High" `
    "net accounts /lockoutthreshold:10" `
    "Locks accounts after 10 failed login attempts"
if (-not $lockoutPass) { Add-Remediation "1.2.1" "Account Lockout Threshold" "net accounts /lockoutthreshold:10" "Protects against brute force attacks" "High" }

$lockoutDurationMatch = $secpolContent | Select-String "LockoutDuration"
if ($lockoutDurationMatch) {
    $lockoutDuration = $lockoutDurationMatch.Line.Split("=")[1].Trim()
    $lockoutDurPass = [int]$lockoutDuration -ge 15
} else {
    $lockoutDuration = "Not configured"
    $lockoutDurPass = $false
}
Add-Result "Account Policy" "1.2.2" "Account Lockout Duration" `
    $(if($lockoutDurPass){"PASS"}else{"FAIL"}) "$lockoutDuration minutes" "15 minutes or more" "Medium" `
    "# Set via: secpol.msc > Account Policies > Account Lockout Policy > Account lockout duration > 15 minutes" `
    "Locked accounts automatically unlock after 15 minutes"
if (-not $lockoutDurPass) { Add-Remediation "1.2.2" "Account Lockout Duration" "`$tempCfg = 'C:\Windows\security\tempSecPol.cfg'; secedit /export /cfg `$tempCfg /quiet; `$content = Get-Content `$tempCfg; `$content = `$content -replace 'LockoutDuration\s*=\s*\d+', 'LockoutDuration = 15'; `$content | Set-Content `$tempCfg; secedit /configure /db C:\Windows\security\local.sdb /cfg `$tempCfg /areas SECURITYPOLICY /quiet; Remove-Item `$tempCfg -Force" "Sets lockout duration to 15 minutes" "Medium"  }

# ============================================
# SECTION 2: LOCAL SECURITY POLICIES
# ============================================
Write-Host "[2/10] Checking Local Security Policies..." -ForegroundColor Green

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$noLMHash = Test-RegistryValue $lsaPath "NoLMHash" 1
Add-Result "Security Options" "2.3.11.7" "No LM Hash Storage" `
    $(if($noLMHash){"PASS"}else{"FAIL"}) $(if($noLMHash){"Enabled"}else{"Disabled"}) "Enabled" "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -PropertyType DWord -Force" `
    "Prevents storage of weak LM password hashes"
if (-not $noLMHash) { Add-Remediation "2.3.11.7" "No LM Hash Storage" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -PropertyType DWord -Force" "Prevents weak password hash storage" "High" }

$restrictAnonymousSAM = Test-RegistryValue $lsaPath "RestrictAnonymousSAM" 1
Add-Result "Security Options" "2.3.10.1" "Restrict Anonymous SAM Enumeration" `
    $(if($restrictAnonymousSAM){"PASS"}else{"FAIL"}) $(if($restrictAnonymousSAM){"Enabled"}else{"Disabled"}) "Enabled" "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -PropertyType DWord -Force" `
    "Blocks anonymous users from listing accounts"
if (-not $restrictAnonymousSAM) { Add-Remediation "2.3.10.1" "Restrict Anonymous SAM" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -PropertyType DWord -Force" "Prevents account enumeration" "High" }

$restrictAnonymous = Test-RegistryValue $lsaPath "RestrictAnonymous" 1
Add-Result "Security Options" "2.3.10.2" "Restrict Anonymous Share Enumeration" `
    $(if($restrictAnonymous){"PASS"}else{"FAIL"}) $(if($restrictAnonymous){"Enabled"}else{"Disabled"}) "Enabled" "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -PropertyType DWord -Force" `
    "Blocks anonymous users from listing network shares"
if (-not $restrictAnonymous) { Add-Remediation "2.3.10.2" "Restrict Anonymous Shares" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -PropertyType DWord -Force" "Prevents share enumeration" "High" }

$lmCompatLevel = Get-RegistryValue $lsaPath "LmCompatibilityLevel"
$lmCompatPass = $lmCompatLevel -ge 5
Add-Result "Security Options" "2.3.11.9" "LAN Manager Authentication Level" `
    $(if($lmCompatPass){"PASS"}else{"FAIL"}) "Level $lmCompatLevel" "Level 5 (NTLMv2 only)" "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -PropertyType DWord -Force" `
    "Forces NTLMv2 authentication only. May affect legacy systems."
if (-not $lmCompatPass) { Add-Remediation "2.3.11.9" "LAN Manager Auth Level" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -PropertyType DWord -Force" "Use NTLMv2 only. Test compatibility first!" "High" }

$everyoneIncludesAnonymous = Test-RegistryValue $lsaPath "EveryoneIncludesAnonymous" 0
Add-Result "Security Options" "2.3.10.3" "Everyone Permissions Do Not Include Anonymous" `
    $(if($everyoneIncludesAnonymous){"PASS"}else{"FAIL"}) $(if($everyoneIncludesAnonymous){"Configured"}else{"Not configured"}) "Configured" "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -PropertyType DWord -Force" `
    "Excludes anonymous users from Everyone group"
if (-not $everyoneIncludesAnonymous) { Add-Remediation "2.3.10.3" "Everyone Excludes Anonymous" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -PropertyType DWord -Force" "Removes anonymous access" "High" }

# ============================================
# SECTION 3: USER ACCOUNT CONTROL
# ============================================
Write-Host "[3/10] Checking User Account Control..." -ForegroundColor Green

$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacEnabled = Test-RegistryValue $uacPath "EnableLUA" 1
Add-Result "UAC" "2.3.17.1" "UAC Enabled" `
    $(if($uacEnabled){"PASS"}else{"FAIL"}) $(if($uacEnabled){"Enabled"}else{"Disabled"}) "Enabled" "Critical" `
    "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -PropertyType DWord -Force" `
    "Enables User Account Control - CRITICAL SECURITY CONTROL"
if (-not $uacEnabled) { Add-Remediation "2.3.17.1" "Enable UAC" "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -PropertyType DWord -Force" "CRITICAL: Enables UAC protection. Restart required." "Critical" }

$uacAdminMode = Get-RegistryValue $uacPath "ConsentPromptBehaviorAdmin"
$uacAdminPass = $uacAdminMode -eq 2
Add-Result "UAC" "2.3.17.2" "UAC Admin Approval Mode" `
    $(if($uacAdminPass){"PASS"}else{"FAIL"}) "Level $uacAdminMode" "Level 2 (Prompt for consent)" "High" `
    "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -PropertyType DWord -Force" `
    "Prompts for consent on elevation"
if (-not $uacAdminPass) { Add-Remediation "2.3.17.2" "UAC Admin Prompt" "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -PropertyType DWord -Force" "Prompts for administrative actions" "High" }

$filterAdminToken = Test-RegistryValue $uacPath "FilterAdministratorToken" 1
Add-Result "UAC" "2.3.17.5" "UAC Admin Approval Mode for Built-in Admin" `
    $(if($filterAdminToken){"PASS"}else{"FAIL"}) $(if($filterAdminToken){"Enabled"}else{"Disabled"}) "Enabled" "High" `
    "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -PropertyType DWord -Force" `
    "Enables UAC for built-in Administrator account"
if (-not $filterAdminToken) { Add-Remediation "2.3.17.5" "UAC for Built-in Admin" "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Value 1 -PropertyType DWord -Force" "Applies UAC to Administrator" "High" }

# ============================================
# SECTION 4: NETWORK SECURITY
# ============================================
Write-Host "[4/10] Checking Network Security..." -ForegroundColor Green

$smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$smbClientSigning = Test-RegistryValue $smbClientPath "RequireSecuritySignature" 1
Add-Result "SMB Security" "2.3.8.3" "SMB Client Signing Required" `
    $(if($smbClientSigning){"PASS"}else{"FAIL"}) $(if($smbClientSigning){"Required"}else{"Not required"}) "Required" "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord -Force" `
    "Requires digitally signed SMB communications"
if (-not $smbClientSigning) { Add-Remediation "2.3.8.3" "SMB Client Signing" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord -Force" "Prevents SMB relay attacks" "High" }

$smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$smbServerSigning = Test-RegistryValue $smbServerPath "RequireSecuritySignature" 1
Add-Result "SMB Security" "2.3.9.2" "SMB Server Signing Required" `
    $(if($smbServerSigning){"PASS"}else{"FAIL"}) $(if($smbServerSigning){"Required"}else{"Not required"}) "Required" "Critical" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord -Force" `
    "CRITICAL: Requires signed SMB server communications"
if (-not $smbServerSigning) { Add-Remediation "2.3.9.2" "SMB Server Signing" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord -Force" "CRITICAL: Protects against SMB attacks" "Critical" }

# Check SMBv1
$smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$smbv1Disabled = if($smbv1){$smbv1.State -eq "Disabled"}else{$true}
Add-Result "SMB Security" "18.3.1" "SMBv1 Protocol Disabled" `
    $(if($smbv1Disabled){"PASS"}else{"FAIL"}) $(if($smbv1Disabled){"Disabled"}else{"Enabled"}) "Disabled" "Critical" `
    "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" `
    "CRITICAL: Disables vulnerable SMBv1. Restart required. Verify no legacy systems need SMBv1."
if (-not $smbv1Disabled) { Add-Remediation "18.3.1" "Disable SMBv1" "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart" "CRITICAL: Remove vulnerable protocol. Test first! Restart needed." "Critical" }

# NetBIOS over TCP/IP
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
$netbiosDisabled = $true
foreach ($adapter in $adapters) {
    if ($adapter.TcpipNetbiosOptions -ne 2) {
        $netbiosDisabled = $false
        break
    }
}
Add-Result "Network Security" "18.4.1" "NetBIOS over TCP/IP Disabled" `
    $(if($netbiosDisabled){"PASS"}else{"WARN"}) $(if($netbiosDisabled){"Disabled"}else{"Enabled"}) "Disabled" "Medium" `
    "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { Invoke-CimMethod -InputObject `$_ -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} }" `
    "Reduces attack surface. May affect legacy applications."
if (-not $netbiosDisabled) { Add-Remediation "18.4.1" "Disable NetBIOS" "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { Invoke-CimMethod -InputObject `$_ -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} }" "Prevents NetBIOS name resolution attacks" "Medium" }

# LLMNR
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$llmnrDisabled = Test-RegistryValue $llmnrPath "EnableMulticast" 0
Add-Result "Network Security" "18.5.1" "LLMNR Disabled" `
    $(if($llmnrDisabled){"PASS"}else{"WARN"}) $(if($llmnrDisabled){"Disabled"}else{"Enabled"}) "Disabled" "High" `
    "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force" `
    "Prevents LLMNR poisoning attacks"
if (-not $llmnrDisabled) { Add-Remediation "18.5.1" "Disable LLMNR" "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force" "Prevents name resolution poisoning" "High" }

# ============================================
# SECTION 5: WINDOWS FIREWALL
# ============================================
Write-Host "[5/10] Checking Windows Firewall..." -ForegroundColor Green

$profiles = @("Domain", "Private", "Public")
foreach ($profile in $profiles) {
    $fwProfile = Get-NetFirewallProfile -Name $profile
    
    $fwEnabled = $fwProfile.Enabled
    Add-Result "Firewall" "9.1.$($profiles.IndexOf($profile)+1)" "Firewall State - $profile" `
        $(if($fwEnabled){"PASS"}else{"FAIL"}) $(if($fwEnabled){"On"}else{"Off"}) "On" "Critical" `
        "Set-NetFirewallProfile -Name $profile -Enabled True" `
        "CRITICAL: Enables Windows Firewall for $profile profile"
    if (-not $fwEnabled) { Add-Remediation "9.1.$($profiles.IndexOf($profile)+1)" "Enable Firewall - $profile" "Set-NetFirewallProfile -Name $profile -Enabled True" "CRITICAL: Enables firewall protection" "Critical" }
    
    # DefaultInboundAction: 1=Allow, 4=Block (numeric enum values)
    $blockInbound = ($fwProfile.DefaultInboundAction -eq "Block") -or ($fwProfile.DefaultInboundAction -eq 4)
    $inboundValue = if($fwProfile.DefaultInboundAction -eq 4){"Block"}elseif($fwProfile.DefaultInboundAction -eq 1){"Allow"}else{$fwProfile.DefaultInboundAction}
    Add-Result "Firewall" "9.2.$($profiles.IndexOf($profile)+1)" "Inbound Connections - $profile" `
        $(if($blockInbound){"PASS"}else{"FAIL"}) $inboundValue "Block" "High" `
        "Set-NetFirewallProfile -Name $profile -DefaultInboundAction Block" `
        "Blocks uninvited inbound connections by default"
    if (-not $blockInbound) { Add-Remediation "9.2.$($profiles.IndexOf($profile)+1)" "Block Inbound - $profile" "Set-NetFirewallProfile -Name $profile -DefaultInboundAction Block" "Blocks unauthorized connections" "High" }
    
    # LogBlocked can be True/False or "True"/"False" (string) or 1/0 (numeric), so check all
    $logBlocked = ($fwProfile.LogBlocked -eq "True") -or ($fwProfile.LogBlocked -eq $true) -or ($fwProfile.LogBlocked -eq 1)
    $logValue = if($fwProfile.LogBlocked -eq 1 -or $fwProfile.LogBlocked -eq $true -or $fwProfile.LogBlocked -eq "True"){"True"}else{"False"}
    Add-Result "Firewall" "9.3.$($profiles.IndexOf($profile)+1)" "Log Dropped Packets - $profile" `
        $(if($logBlocked){"PASS"}else{"WARN"}) $logValue "True" "Medium" `
        "Set-NetFirewallProfile -Name $profile -LogBlocked True" `
        "Enables logging of blocked connections for security monitoring"
    if (-not $logBlocked) { Add-Remediation "9.3.$($profiles.IndexOf($profile)+1)" "Log Blocked - $profile" "Set-NetFirewallProfile -Name $profile -LogBlocked True" "Enables security monitoring" "Medium" }
}

# ============================================
# SECTION 6: REMOTE ACCESS
# ============================================
Write-Host "[6/10] Checking Remote Access Controls..." -ForegroundColor Green

$rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpEnabled = Get-RegistryValue $rdpPath "fDenyTSConnections"
$nlaEnabled = Test-RegistryValue "$rdpPath\WinStations\RDP-Tcp" "UserAuthentication" 1

# Determine RDP status
if ($rdpEnabled -eq 1) {
    # RDP is disabled - PASS
    $rdpStatus = "PASS"
    $rdpCurrent = "Disabled"
    $rdpExpected = "Disabled or NLA enabled"
} elseif ($rdpEnabled -eq 0 -and $nlaEnabled) {
    # RDP is enabled WITH NLA - PASS
    $rdpStatus = "PASS"
    $rdpCurrent = "Enabled with NLA"
    $rdpExpected = "Disabled or NLA enabled"
} elseif ($rdpEnabled -eq 0 -and -not $nlaEnabled) {
    # RDP is enabled WITHOUT NLA - FAIL
    $rdpStatus = "FAIL"
    $rdpCurrent = "Enabled without NLA"
    $rdpExpected = "Disabled or NLA enabled"
} else {
    # Unknown state
    $rdpStatus = "INFO"
    $rdpCurrent = "Unknown"
    $rdpExpected = "Disabled or NLA enabled"
}

Add-Result "Remote Desktop" "18.9.60.2" "Remote Desktop Status" `
    $rdpStatus $rdpCurrent $rdpExpected "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -PropertyType DWord -Force" `
    "If RDP is enabled, NLA must be enabled for security."

# Only add remediation if RDP is enabled without NLA
if ($rdpEnabled -eq 0 -and -not $nlaEnabled) {
    Add-Remediation "18.9.60.2" "Enable NLA for RDP" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -PropertyType DWord -Force" "Enables NLA to secure RDP. Does not disable RDP." "High"
}

# Remove the old NLA check since we've incorporated it above
# (Delete the separate NLA check that comes after this)

$securityLayer = Get-RegistryValue "$rdpPath\WinStations\RDP-Tcp" "SecurityLayer"
$secLayerPass = $securityLayer -eq 2
Add-Result "Remote Desktop" "18.9.60.4" "RDP Security Layer" `
    $(if($secLayerPass){"PASS"}else{"WARN"}) $(if($securityLayer -eq 2){"SSL/TLS"}else{"Value $securityLayer"}) "SSL/TLS (2)" "Medium" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2 -PropertyType DWord -Force" `
    "Enforces TLS 1.0 encryption for RDP"
if (-not $secLayerPass) { Add-Remediation "18.9.60.4" "RDP Security Layer" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2 -PropertyType DWord -Force" "Use TLS encryption" "Medium" }

$encryptionLevel = Get-RegistryValue "$rdpPath\WinStations\RDP-Tcp" "MinEncryptionLevel"
$encLevelPass = $encryptionLevel -eq 3
Add-Result "Remote Desktop" "18.9.60.5" "RDP Encryption Level" `
    $(if($encLevelPass){"PASS"}else{"WARN"}) $(if($encryptionLevel -eq 3){"High"}else{"Value $encryptionLevel"}) "High (3)" "Medium" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3 -PropertyType DWord -Force" `
    "Sets RDP encryption to High (128-bit)"
if (-not $encLevelPass) { Add-Remediation "18.9.60.5" "RDP Encryption Level" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3 -PropertyType DWord -Force" "Use 128-bit encryption" "Medium" }

# ============================================
# SECTION 7: CRITICAL SERVICES
# ============================================
Write-Host "[7/10] Checking Critical Services..." -ForegroundColor Green

$criticalServices = @(
    @{Name="RemoteRegistry"; ShouldBe="Disabled"; Severity="High"; Control="5.1"},
    @{Name="SSDPSRV"; ShouldBe="Disabled"; Severity="Medium"; Control="5.2"},
    @{Name="upnphost"; ShouldBe="Disabled"; Severity="Medium"; Control="5.3"},
    @{Name="WinRM"; ShouldBe="Disabled"; Severity="High"; Control="5.4"}
)

foreach ($svc in $criticalServices) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        $startType = (Get-Service -Name $svc.Name).StartType
        $shouldDisable = $startType -ne "Disabled" -and $svc.ShouldBe -eq "Disabled"
        $status = if($startType -eq "Disabled"){"PASS"}elseif($svc.ShouldBe -eq "Disabled"){"WARN"}else{"PASS"}
        Add-Result "Services" $svc.Control "$($svc.Name) Service" `
            $status "$startType" $svc.ShouldBe $svc.Severity `
            "Stop-Service -Name '$($svc.Name)' -Force; Set-Service -Name '$($svc.Name)' -StartupType Disabled" `
            "Disables $($svc.Name) service to reduce attack surface"
        if ($shouldDisable) { Add-Remediation $svc.Control "$($svc.Name) Service" "Stop-Service -Name '$($svc.Name)' -Force -ErrorAction SilentlyContinue; Set-Service -Name '$($svc.Name)' -StartupType Disabled" "Reduces attack surface. Verify not needed first." $svc.Severity }
    }
}

# ============================================
# SECTION 8: AUDIT POLICIES
# ============================================
Write-Host "[8/10] Checking Audit Policies..." -ForegroundColor Green

$auditCategories = @(
    @{Category="Logon"; SubCategory="Logon"; Expected="Success and Failure"; Control="17.1.1"; SuccessFailure=$true},
    @{Category="Logon"; SubCategory="Logoff"; Expected="Success"; Control="17.1.2"; SuccessFailure=$false},
    @{Category="Logon"; SubCategory="Account Lockout"; Expected="Failure"; Control="17.1.3"; SuccessFailure=$false},
    @{Category="Account Management"; SubCategory="User Account Management"; Expected="Success and Failure"; Control="17.2.1"; SuccessFailure=$true},
    @{Category="Policy Change"; SubCategory="Audit Policy Change"; Expected="Success and Failure"; Control="17.5.1"; SuccessFailure=$true},
    @{Category="Privilege Use"; SubCategory="Sensitive Privilege Use"; Expected="Success and Failure"; Control="17.6.1"; SuccessFailure=$true}
)

foreach ($audit in $auditCategories) {
    $auditResult = auditpol /get /subcategory:"$($audit.SubCategory)" 2>$null
    $configured = ($auditResult | Select-String $audit.Expected).Matches.Success
    $auditCmd = if($audit.SuccessFailure){
        "auditpol /set /subcategory:`"$($audit.SubCategory)`" /success:enable /failure:enable"
    } elseif($audit.Expected -eq "Success") {
        "auditpol /set /subcategory:`"$($audit.SubCategory)`" /success:enable /failure:disable"
    } else {
        "auditpol /set /subcategory:`"$($audit.SubCategory)`" /success:disable /failure:enable"
    }
    Add-Result "Audit Policy" $audit.Control "Audit $($audit.SubCategory)" `
        $(if($configured){"PASS"}else{"FAIL"}) $(if($configured){$audit.Expected}else{"Not configured"}) $audit.Expected "Medium" `
        $auditCmd `
        "Enables auditing for $($audit.SubCategory) events"
    if (-not $configured) { Add-Remediation $audit.Control "Audit $($audit.SubCategory)" $auditCmd "Enables security event logging" "Medium" }
}

# ============================================
# SECTION 9: LOCAL ACCOUNTS
# ============================================
Write-Host "[9/10] Checking Local Accounts..." -ForegroundColor Green

$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
$guestDisabled = if($guest){-not $guest.Enabled}else{$true}
Add-Result "Local Accounts" "2.3.1.3" "Guest Account Status" `
    $(if($guestDisabled){"PASS"}else{"FAIL"}) $(if($guestDisabled){"Disabled"}else{"Enabled"}) "Disabled" "High" `
    "Disable-LocalUser -Name 'Guest'" `
    "Disables the Guest account to prevent unauthorized access"
if (-not $guestDisabled) { Add-Remediation "2.3.1.3" "Disable Guest Account" "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue" "Prevents anonymous access" "High" }

$admin = Get-LocalUser | Where-Object {$_.SID -like "*-500"}
$adminRenamed = if($admin){$admin.Name -ne "Administrator"}else{$false}
Add-Result "Local Accounts" "2.3.1.1" "Administrator Account Renamed" `
    $(if($adminRenamed){"PASS"}else{"WARN"}) $(if($adminRenamed){"Renamed to $($admin.Name)"}else{"Not renamed"}) "Renamed" "Medium" `
    "Rename-LocalUser -Name 'Administrator' -NewName 'SysAdmin'" `
    "Renames Administrator to SysAdmin. Change 'SysAdmin' to a unique name for better security."
if (-not $adminRenamed) { Add-Remediation "2.3.1.1" "Rename Administrator" "Rename-LocalUser -Name 'Administrator' -NewName 'SysAdmin' -ErrorAction Stop" "Renames to SysAdmin. Choose a unique non-obvious name for better security." "Medium" }

# ============================================
# SECTION 10: WINDOWS DEFENDER & SECURITY
# ============================================
Write-Host "[10/10] Checking Windows Defender & Security..." -ForegroundColor Green

try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    
    $avEnabled = $defender.AntivirusEnabled
    Add-Result "Antivirus" "18.9.44.1" "Windows Defender Enabled" `
        $(if($avEnabled){"PASS"}else{"FAIL"}) $(if($avEnabled){"Enabled"}else{"Disabled"}) "Enabled" "Critical" `
        "Set-MpPreference -DisableRealtimeMonitoring `$false" `
        "CRITICAL: Enables Windows Defender antivirus protection"
    if (-not $avEnabled) { Add-Remediation "18.9.44.1" "Enable Defender" "Set-MpPreference -DisableRealtimeMonitoring `$false" "CRITICAL: Enables antivirus protection" "Critical" }
    
    $rtEnabled = $defender.RealTimeProtectionEnabled
    Add-Result "Antivirus" "18.9.44.2" "Real-time Protection" `
        $(if($rtEnabled){"PASS"}else{"FAIL"}) $(if($rtEnabled){"Enabled"}else{"Disabled"}) "Enabled" "Critical" `
        "Set-MpPreference -DisableRealtimeMonitoring `$false" `
        "CRITICAL: Enables real-time threat detection"
    if (-not $rtEnabled) { Add-Remediation "18.9.44.2" "Enable Real-time Protection" "Set-MpPreference -DisableRealtimeMonitoring `$false" "CRITICAL: Real-time threat scanning" "Critical" }
    
    $behaviorEnabled = $defender.BehaviorMonitorEnabled
    Add-Result "Antivirus" "18.9.44.3" "Behavior Monitoring" `
        $(if($behaviorEnabled){"PASS"}else{"WARN"}) $(if($behaviorEnabled){"Enabled"}else{"Disabled"}) "Enabled" "High" `
        "Set-MpPreference -DisableBehaviorMonitoring `$false" `
        "Monitors suspicious application behavior"
    if (-not $behaviorEnabled) { Add-Remediation "18.9.44.3" "Enable Behavior Monitoring" "Set-MpPreference -DisableBehaviorMonitoring `$false" "Detects suspicious behavior" "High" }
    
    $ioavEnabled = $defender.IoavProtectionEnabled
    Add-Result "Antivirus" "18.9.44.4" "IOAV Protection" `
        $(if($ioavEnabled){"PASS"}else{"WARN"}) $(if($ioavEnabled){"Enabled"}else{"Disabled"}) "Enabled" "High" `
        "Set-MpPreference -DisableIOAVProtection `$false" `
        "Scans downloaded files and attachments"
    if (-not $ioavEnabled) { Add-Remediation "18.9.44.4" "Enable IOAV Protection" "Set-MpPreference -DisableIOAVProtection `$false" "Scans downloads automatically" "High" }
    
    $defAge = (Get-Date) - $defender.AntivirusSignatureLastUpdated
    $sigCurrent = $defAge.Days -le 7
    Add-Result "Antivirus" "18.9.44.5" "Signature Age" `
        $(if($sigCurrent){"PASS"}elseif($defAge.Days -le 14){"WARN"}else{"FAIL"}) "$($defAge.Days) days old" "7 days or newer" "High" `
        "Update-MpSignature" `
        "Updates virus definitions to latest version"
    if (-not $sigCurrent) { Add-Remediation "18.9.44.5" "Update Defender Signatures" "Update-MpSignature" "Updates to latest threat definitions" "High" }
        
} catch {
    Add-Result "Antivirus" "18.9.44" "Windows Defender Status" "ERROR" "Cannot determine" "Enabled and updated" "Critical" `
        "# Verify Windows Defender is installed and running" `
        "Unable to query Defender status"
}

# LSA Protection
$lsaProtection = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
$lsaProtected = $lsaProtection -eq 1
Add-Result "Credential Protection" "18.8.1" "LSA Protection" `
    $(if($lsaProtected){"PASS"}else{"WARN"}) $(if($lsaProtected){"Enabled"}else{"Disabled"}) "Enabled" "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -PropertyType DWord -Force" `
    "Protects credentials in memory. Restart required."
if (-not $lsaProtected) { Add-Remediation "18.8.1" "Enable LSA Protection" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -PropertyType DWord -Force" "Protects against credential theft. Restart needed." "High" }

# WDigest Authentication
$wdigest = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
$wdigestDisabled = $wdigest -eq 0
Add-Result "Credential Protection" "18.8.2" "WDigest Authentication Disabled" `
    $(if($wdigestDisabled){"PASS"}else{"FAIL"}) $(if($wdigestDisabled){"Disabled"}else{"Enabled"}) "Disabled" "High" `
    "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -PropertyType DWord -Force" `
    "Prevents plaintext password storage in memory"
if (-not $wdigestDisabled) { Add-Remediation "18.8.2" "Disable WDigest" "New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -PropertyType DWord -Force" "Prevents password in memory" "High" }

Write-Host "`nGenerating reports..." -ForegroundColor Cyan

# Calculate statistics
$passed = ($results | Where-Object {$_.Status -eq "PASS"}).Count
$failed = ($results | Where-Object {$_.Status -eq "FAIL"}).Count
$warnings = ($results | Where-Object {$_.Status -eq "WARN"}).Count
$errors = ($results | Where-Object {$_.Status -eq "ERROR"}).Count
$critical = ($results | Where-Object {$_.Severity -eq "Critical" -and $_.Status -ne "PASS"}).Count
$high = ($results | Where-Object {$_.Severity -eq "High" -and $_.Status -ne "PASS"}).Count
$total = $results.Count
$passRate = [math]::Round(($passed / $total) * 100, 2)

# Generate HTML Report
$html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CIS Server Hardening Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5; padding: 20px; }
        .container { max-width: 1600px; margin: 0 auto; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 30px; font-size: 28px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; font-size: 22px; }
        
        .summary { background: white; padding: 25px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 20px; }
        .summary-item { text-align: center; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px; color: white; }
        .summary-item.pass { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .summary-item.fail { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }
        .summary-item.warn { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .summary-item .number { font-size: 36px; font-weight: bold; margin-bottom: 8px; }
        .summary-item .label { font-size: 13px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.9; }
        
        .risk-summary { background: white; padding: 25px; border-radius: 8px; margin-bottom: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .risk-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .risk-item { padding: 15px; border-left: 4px solid; border-radius: 4px; }
        .risk-item.critical { background: #ffe5e5; border-color: #c0392b; }
        .risk-item.high { background: #fff3e0; border-color: #e67e22; }
        .risk-item .risk-label { font-weight: bold; margin-bottom: 5px; }
        .risk-item.critical .risk-label { color: #c0392b; }
        .risk-item.high .risk-label { color: #e67e22; }
        
        .compliance-bar { background: #ecf0f1; height: 40px; border-radius: 20px; overflow: hidden; margin: 20px 0; }
        .compliance-fill { height: 100%; background: linear-gradient(90deg, #11998e 0%, #38ef7d 100%); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; transition: width 0.5s; }
        .compliance-fill.medium { background: linear-gradient(90deg, #f093fb 0%, #f5576c 100%); }
        .compliance-fill.low { background: linear-gradient(90deg, #eb3349 0%, #f45c43 100%); }
        
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-top: 20px; border-radius: 8px; overflow: hidden; }
        th { background-color: #34495e; color: white; padding: 15px; text-align: left; font-weight: 600; font-size: 13px; }
        td { padding: 12px 15px; border-bottom: 1px solid #ecf0f1; font-size: 13px; vertical-align: top; }
        tr:hover { background-color: #f8f9fa; }
        tr:last-child td { border-bottom: none; }
        
        .status { font-weight: bold; padding: 6px 12px; border-radius: 4px; display: inline-block; font-size: 11px; text-transform: uppercase; }
        .status.PASS { background-color: #d4edda; color: #155724; }
        .status.FAIL { background-color: #f8d7da; color: #721c24; }
        .status.WARN { background-color: #fff3cd; color: #856404; }
        .status.ERROR { background-color: #d6d8db; color: #383d41; }
        
        .severity { padding: 4px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; display: inline-block; }
        .severity.Critical { background-color: #c0392b; color: white; }
        .severity.High { background-color: #e67e22; color: white; }
        .severity.Medium { background-color: #f39c12; color: white; }
        .severity.Low { background-color: #3498db; color: white; }
        
        .remediation { font-size: 12px; color: #7f8c8d; margin-top: 8px; padding: 8px; background: #f8f9fa; border-radius: 4px; font-family: 'Courier New', monospace; }
        .remediation-note { font-size: 11px; color: #95a5a6; margin-top: 4px; font-style: italic; }
        
        .category-section { margin-bottom: 40px; }
        .category-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 20px; border-radius: 8px 8px 0 0; font-size: 18px; font-weight: bold; }
        
        .footer { margin-top: 40px; padding: 25px; background: white; border-radius: 8px; text-align: center; color: #7f8c8d; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .footer p { margin: 5px 0; }
        
        .legend { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .legend-items { display: flex; flex-wrap: wrap; gap: 20px; margin-top: 10px; }
        .legend-item { display: flex; align-items: center; gap: 8px; }
        
        .export-notice { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .export-notice h3 { margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#x1F6E1;&#xFE0F; Windows Server CIS Hardening Assessment Report</h1>
"@

if ($ExportRemediation -and $remediationSteps.Count -gt 0) {
    $html += @"
        <div class="export-notice">
            <h3>Remediation Script Generated</h3>
            <p>A PowerShell remediation script has been exported to: <strong>$RemediationPath</strong></p>
            <p style="font-size: 14px; margin-top: 10px;">Review the script before execution. Some changes require system restart.</p>
        </div>
"@
}

$html += @"
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="compliance-bar">
                <div class="compliance-fill $(if($passRate -ge 80){''}elseif($passRate -ge 60){'medium'}else{'low'})" style="width: $passRate%">
                    $passRate% Compliant
                </div>
            </div>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="number">$total</div>
                    <div class="label">Total Controls</div>
                </div>
                <div class="summary-item pass">
                    <div class="number">$passed</div>
                    <div class="label">Passed</div>
                </div>
                <div class="summary-item fail">
                    <div class="number">$failed</div>
                    <div class="label">Failed</div>
                </div>
                <div class="summary-item warn">
                    <div class="number">$warnings</div>
                    <div class="label">Warnings</div>
                </div>
            </div>
        </div>
        
        <div class="risk-summary">
            <h2>Risk Summary</h2>
            <div class="risk-grid">
                <div class="risk-item critical">
                    <div class="risk-label">CRITICAL ISSUES</div>
                    <div style="font-size: 24px; font-weight: bold; color: #c0392b;">$critical</div>
                    <div style="font-size: 12px; margin-top: 5px;">Require immediate attention</div>
                </div>
                <div class="risk-item high">
                    <div class="risk-label">HIGH PRIORITY</div>
                    <div style="font-size: 24px; font-weight: bold; color: #e67e22;">$high</div>
                    <div style="font-size: 12px; margin-top: 5px;">Should be addressed soon</div>
                </div>
            </div>
        </div>
        
        <div class="legend">
            <h2>Status Legend</h2>
            <div class="legend-items">
                <div class="legend-item">
                    <span class="status PASS">PASS</span>
                    <span>Control meets CIS benchmark</span>
                </div>
                <div class="legend-item">
                    <span class="status FAIL">FAIL</span>
                    <span>Control does not meet benchmark</span>
                </div>
                <div class="legend-item">
                    <span class="status WARN">WARN</span>
                    <span>Review recommended</span>
                </div>
                <div class="legend-item">
                    <span class="status ERROR">ERROR</span>
                    <span>Unable to determine status</span>
                </div>
            </div>
        </div>
        
        <h2>Detailed Findings by Category</h2>
"@

# Group results by category
$categories = $results | Group-Object -Property Category | Sort-Object Name

foreach ($category in $categories) {
    $categoryResults = $category.Group
    $categoryPass = ($categoryResults | Where-Object {$_.Status -eq "PASS"}).Count
    $categoryTotal = $categoryResults.Count
    $categoryRate = [math]::Round(($categoryPass / $categoryTotal) * 100, 0)
    
    $html += @"
        <div class="category-section">
            <div class="category-header">
                $($category.Name) - $categoryPass/$categoryTotal Passed ($categoryRate%)
            </div>
            <table>
                <tr>
                    <th style="width: 7%;">Control</th>
                    <th style="width: 20%;">Description</th>
                    <th style="width: 8%;">Status</th>
                    <th style="width: 8%;">Severity</th>
                    <th style="width: 15%;">Current</th>
                    <th style="width: 15%;">Expected</th>
                    <th style="width: 27%;">Remediation</th>
                </tr>
"@
    
    foreach ($result in $categoryResults) {
        $remediationCell = ""
        if ($result.Status -ne "PASS" -and $result.RemediationScript -ne "") {
            $remediationCell = "<div class='remediation'>$($result.RemediationScript -replace '<','&lt;' -replace '>','&gt;')</div>"
            if ($result.RemediationNote -ne "") {
                $remediationCell += "<div class='remediation-note'>$($result.RemediationNote)</div>"
            }
        } elseif ($result.Status -eq "PASS") {
            $remediationCell = "<span style='color: #27ae60;'>&#10003; Compliant</span>"
        }
        
        $html += @"
                <tr>
                    <td>$($result.Control)</td>
                    <td><strong>$($result.Description)</strong></td>
                    <td><span class="status $($result.Status)">$($result.Status)</span></td>
                    <td><span class="severity $($result.Severity)">$($result.Severity)</span></td>
                    <td>$($result.CurrentValue)</td>
                    <td>$($result.ExpectedValue)</td>
                    <td>$remediationCell</td>
                </tr>
"@
    }
    
    $html += @"
            </table>
        </div>
"@
}

$html += @"
        <div class="footer">
            <p><strong>Assessment completed on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></p>
            <p>System: <strong>$env:COMPUTERNAME</strong> | User: <strong>$env:USERNAME</strong></p>
            <p>OS: <strong>$((Get-WmiObject Win32_OperatingSystem).Caption)</strong></p>
            <p style="margin-top: 15px; font-size: 12px;">This assessment checks essential CIS benchmark controls for Windows Server hardening.</p>
            <p style="font-size: 12px;">For complete CIS compliance, please refer to the official CIS Benchmarks at cisecurity.org</p>
        </div>
    </div>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8NoBOM

# Generate Remediation Script
if ($ExportRemediation -and $remediationSteps.Count -gt 0) {
        
$remediationScript = @"
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    CIS Hardening Remediation Script
.DESCRIPTION
    Automatically applies fixes for failed CIS controls identified in assessment
.NOTES
    **IMPORTANT**: Review this script before execution!
    - Some changes require system restart
    - Test in non-production environment first
    - Back up system before applying changes
    - Some settings may impact legacy applications
    
    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    System: $env:COMPUTERNAME
#>

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "CIS Hardening Remediation Script" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: This script will make security configuration changes." -ForegroundColor Yellow
Write-Host "Make sure you have:" -ForegroundColor Yellow
Write-Host "  1. Reviewed all changes below" -ForegroundColor Yellow
Write-Host "  2. Backed up your system" -ForegroundColor Yellow
Write-Host "  3. Tested in non-production environment" -ForegroundColor Yellow
Write-Host ""

`$continue = Read-Host "Do you want to continue? (yes/no)"
if (`$continue -ne "yes") {
    Write-Host "Remediation cancelled." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "Starting remediation process..." -ForegroundColor Green
Write-Host ""

`$successCount = 0
`$failCount = 0
`$restartRequired = `$false

"@
    
    # Sort by severity (Critical first)
    $sortedRemediation = $remediationSteps | Sort-Object @{Expression={
        switch ($_.Severity) {
            "Critical" { 1 }
            "High" { 2 }
            "Medium" { 3 }
            "Low" { 4 }
        }
    }}
    

    # Build complete script using StreamWriter for better control
$streamWriter = New-Object System.IO.StreamWriter($RemediationPath, $false, [System.Text.Encoding]::UTF8)

try {
        $streamWriter.Write($remediationScript)
                
        foreach ($remediation in $sortedRemediation) {
            $streamWriter.WriteLine("")
            $streamWriter.WriteLine("# ===================================================================")
            $streamWriter.WriteLine("# Control $($remediation.Control): $($remediation.Description)")
            $streamWriter.WriteLine("# Severity: $($remediation.Severity)")
            $streamWriter.WriteLine("# Note: $($remediation.Note)")
            $streamWriter.WriteLine("# ===================================================================")
            $streamWriter.WriteLine("Write-Host `"[$($remediation.Severity)] Applying: $($remediation.Description)...`" -ForegroundColor $(if($remediation.Severity -eq "Critical"){"Red"}elseif($remediation.Severity -eq "High"){"Yellow"}else{"White"})")
            $streamWriter.WriteLine("try {")
            
            # Split the remediation script into separate lines if it contains semicolons
            $scriptLines = $remediation.Script -split ';' | Where-Object { $_.Trim() -ne "" }
            foreach ($scriptLine in $scriptLines) {
                $streamWriter.WriteLine("    " + $scriptLine.Trim())
            }
            
            $streamWriter.WriteLine("    Write-Host `"  ✓ Success`" -ForegroundColor Green")
            
            # DIAGNOSTIC: Let's see what's happening
            $streamWriter.WriteLine("    `$successCount++")
                        
            # Add restart flag if needed
            if ($remediation.Script -match "SMB1Protocol|RunAsPPL") {
                $streamWriter.WriteLine("    `$restartRequired = `$true")
                } else {
            }
            
            $streamWriter.WriteLine("} catch {")
            $streamWriter.WriteLine("    Write-Host `"  ✗ Failed: `$(`$_.Exception.Message)`" -ForegroundColor Red")
            $streamWriter.WriteLine("    `$failCount++")
            $streamWriter.WriteLine("}")
        }
                
        # Write footer
        $streamWriter.Write(@"

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "Remediation Complete" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "Successful: `$successCount" -ForegroundColor Green
Write-Host "Failed: `$failCount" -ForegroundColor Red
Write-Host ""

if (`$restartRequired) {
    Write-Host "RESTART REQUIRED for changes to take effect!" -ForegroundColor Yellow
    Write-Host ""
    `$restart = Read-Host "Restart now? (yes/no)"
    if (`$restart -eq "yes") {
        Write-Host "Restarting in 30 seconds..." -ForegroundColor Yellow
        shutdown /r /t 30 /c "CIS Hardening - Restart required for security changes"
    } else {
        Write-Host "Please restart your system manually to complete remediation." -ForegroundColor Yellow
    }
} else {
    Write-Host "No restart required." -ForegroundColor Green
}

Write-Host ""
Write-Host "Re-run the assessment script to verify changes." -ForegroundColor Cyan
"@)
    }
    catch {
        Write-Host "ERROR in StreamWriter: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "ERROR Stack: $($_.ScriptStackTrace)" -ForegroundColor Red
    }
    finally {
            if ($streamWriter) {
            $streamWriter.Flush()
            $streamWriter.Close()
            $streamWriter.Dispose()
        }
    }
    
    Write-Host "Remediation script exported to: $RemediationPath" -ForegroundColor Green
}

# Clean up temp file
Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue

# Display summary in console
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Assessment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`nOVERALL COMPLIANCE" -ForegroundColor White
Write-Host "Total Controls Checked: $total" -ForegroundColor White
Write-Host "Passed: " -NoNewline; Write-Host "$passed" -ForegroundColor Green
Write-Host "Failed: " -NoNewline; Write-Host "$failed" -ForegroundColor Red
Write-Host "Warnings: " -NoNewline; Write-Host "$warnings" -ForegroundColor Yellow
if ($errors -gt 0) { Write-Host "Errors: " -NoNewline; Write-Host "$errors" -ForegroundColor Gray }
Write-Host "`nCompliance Rate: " -NoNewline
Write-Host "$passRate%" -ForegroundColor $(if($passRate -ge 80){'Green'}elseif($passRate -ge 60){'Yellow'}else{'Red'})

Write-Host "`nRISK ASSESSMENT" -ForegroundColor White
Write-Host "Critical Issues: " -NoNewline; Write-Host "$critical" -ForegroundColor $(if($critical -gt 0){'Red'}else{'Green'})
Write-Host "High Priority Issues: " -NoNewline; Write-Host "$high" -ForegroundColor $(if($high -gt 0){'Yellow'}else{'Green'})

Write-Host "`nREPORTS GENERATED" -ForegroundColor White
Write-Host "Assessment Report: " -NoNewline -ForegroundColor Cyan
Write-Host "$OutputPath" -ForegroundColor White
if ($ExportRemediation -and $remediationSteps.Count -gt 0) {
    Write-Host "Remediation Script: " -NoNewline -ForegroundColor Cyan
    Write-Host "$RemediationPath" -ForegroundColor White
    Write-Host "  → Run remediation script to automatically fix $($remediationSteps.Count) issues" -ForegroundColor Yellow
}
Write-Host "========================================`n" -ForegroundColor Cyan

# Show critical failures
$criticalFailed = $results | Where-Object {$_.Severity -eq "Critical" -and $_.Status -ne "PASS"}
if ($criticalFailed.Count -gt 0) {
    Write-Host "CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:" -ForegroundColor Red
    Write-Host "=================================================" -ForegroundColor Red
    foreach ($issue in $criticalFailed) {
        Write-Host "  [!] $($issue.Description)" -ForegroundColor Red
        Write-Host "      Current: $($issue.CurrentValue) | Expected: $($issue.ExpectedValue)" -ForegroundColor Yellow
        if ($issue.RemediationScript -ne "") {
            Write-Host "      Fix: $($issue.RemediationScript)" -ForegroundColor Cyan
        }
        Write-Host ""
    }
}

# Show high priority failures
$highFailed = $results | Where-Object {$_.Severity -eq "High" -and $_.Status -ne "PASS"}
if ($highFailed.Count -gt 0) {
    Write-Host "HIGH PRIORITY ISSUES:" -ForegroundColor Yellow
    Write-Host "========================" -ForegroundColor Yellow
    foreach ($issue in $highFailed | Select-Object -First 5) {
        Write-Host "  [!] $($issue.Description)" -ForegroundColor Yellow
        Write-Host "      Current: $($issue.CurrentValue) | Expected: $($issue.ExpectedValue)" -ForegroundColor White
    }
    if ($highFailed.Count -gt 5) {
        Write-Host "  ... and $($highFailed.Count - 5) more (see report for details)" -ForegroundColor Gray
    }
    Write-Host ""
}

# Recommendations
if ($failed -gt 0 -or $warnings -gt 0) {
    Write-Host "NEXT STEPS:" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    if ($ExportRemediation -and $remediationSteps.Count -gt 0) {
        Write-Host "1. Review the remediation script: $RemediationPath" -ForegroundColor White
        Write-Host "2. Test in non-production environment first" -ForegroundColor White
        Write-Host "3. Back up your system" -ForegroundColor White
        Write-Host "4. Run the remediation script as Administrator" -ForegroundColor White
        Write-Host "5. Re-run this assessment to verify fixes" -ForegroundColor White
    } else {
        Write-Host "1. Review the detailed report: $OutputPath" -ForegroundColor White
        Write-Host "2. Re-run with -ExportRemediation switch to generate fix script:" -ForegroundColor White
        Write-Host "   .\CIS-Assessment.ps1 -ExportRemediation" -ForegroundColor Cyan
    }
    Write-Host ""
}

# Open report
$open = Read-Host "Open HTML report in browser? (Y/N)"
if ($open -eq 'Y' -or $open -eq 'y') {
    Start-Process $OutputPath
}

if ($ExportRemediation -and $remediationSteps.Count -gt 0) {
    Write-Host "`nIMPORTANT: Review remediation script before running!" -ForegroundColor Yellow
    $openRemed = Read-Host "Open remediation script for review? (Y/N)"
    if ($openRemed -eq 'Y' -or $openRemed -eq 'y') {
        notepad $RemediationPath
    }
}
