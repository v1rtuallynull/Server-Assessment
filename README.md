# Windows Server CIS Hardening Assessment Tool

A PowerShell-based tool for assessing Windows Server systems against CIS (Center for Internet Security) benchmark controls and automatically generating remediation scripts.

## Features

- **Automated Assessment**: Evaluates 51 essential CIS benchmark controls for Windows Server hardening
- **Professional HTML Reports**: Generates detailed, color-coded compliance reports with visual summaries
- **Automatic Remediation**: Exports executable PowerShell scripts to fix failed controls
- **Severity-Based Prioritization**: Controls categorized as Critical, High, Medium, or Low priority
- **Safe Testing**: Review-before-execute approach with detailed remediation notes
- **Comprehensive Coverage**: Checks across 10 security categories

## Security Categories Assessed

1. **Account Policies** - Password requirements, lockout policies
2. **Local Security Policies** - Authentication levels, anonymous access restrictions
3. **User Account Control (UAC)** - Privilege elevation settings
4. **Network Security** - SMB signing, SMBv1 status, NetBIOS, LLMNR
5. **Windows Firewall** - Profile states, inbound rules, logging
6. **Remote Access** - RDP configuration, NLA, encryption levels
7. **Critical Services** - Unnecessary service identification
8. **Audit Policies** - Security event logging configuration
9. **Local Accounts** - Guest account, Administrator account status
10. **Windows Defender & Credential Protection** - Antivirus, LSA protection, WDigest

## Requirements

- Windows Server (tested on Server 2016, 2019, 2022)
- PowerShell 5.1 or higher
- Administrator privileges
- Execution policy allowing script execution

## Installation

1. Clone this repository:
```powershell
git clone https://github.com/v1rtuallynull/Server-Assessment.git
cd Server-Assessment
```

2. Ensure you're running PowerShell as Administrator

3. Set execution policy if needed:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Usage

### Basic Assessment

Run a basic assessment and generate an HTML report:
```powershell
.\CIS-Assessment.ps1
```

### Assessment with Remediation Script

Generate both an assessment report and a remediation script:
```powershell
.\CIS-Assessment.ps1 -ExportRemediation
```

### Custom Output Paths

Specify custom paths for the output files:
```powershell
.\CIS-Assessment.ps1 -OutputPath "C:\Reports\Assessment.html" -RemediationPath "C:\Scripts\Remediation.ps1" -ExportRemediation
```

## Output Files

- **HTML Assessment Report**: Visual report showing compliance status, risk summary, and detailed findings
- **PowerShell Remediation Script**: Executable script to automatically fix failed controls

## Remediation Workflow

**⚠️ IMPORTANT: Always test in a non-production environment first!**

1. Run the assessment with `-ExportRemediation`
2. Review the generated remediation script
3. Back up your system or take a VM snapshot
4. Run the remediation script as Administrator
5. Reboot if prompted (required for SMBv1 removal, LSA Protection)
6. Re-run the assessment to verify improvements

### Example Remediation Process
```powershell
# Step 1: Initial assessment
.\CIS-Assessment.ps1 -ExportRemediation

# Step 2: Review the remediation script
notepad .\CIS_Remediation_YYYYMMDD_HHMMSS.ps1

# Step 3: Run remediation (after review and backup!)
.\CIS_Remediation_YYYYMMDD_HHMMSS.ps1

# Step 4: Reboot if needed
Restart-Computer

# Step 5: Verify compliance improved
.\CIS-Assessment.ps1
```

## Understanding the Report

### Status Indicators

- **PASS** (Green): Control meets CIS benchmark requirements
- **FAIL** (Red): Control does not meet benchmark - remediation available
- **WARN** (Yellow): Control requires review or manual intervention
- **ERROR** (Gray): Unable to determine status

### Severity Levels

- **Critical**: Requires immediate attention (e.g., firewall disabled, SMBv1 enabled)
- **High**: Should be addressed promptly (e.g., weak authentication, missing audit logs)
- **Medium**: Important but less urgent (e.g., password age limits)
- **Low**: Best practice improvements

### Compliance Rate

The report calculates an overall compliance percentage:
- **80%+**: Good compliance
- **60-79%**: Moderate compliance, improvements needed
- **<60%**: Significant hardening required

## Controls That Require Restart

The following remediations require a system restart:
- **SMBv1 Protocol Removal** (Control 18.3.1)
- **LSA Protection** (Control 18.8.1)

The remediation script will prompt you to restart when needed.

## Known Limitations

- **Password Complexity & Account Lockout Duration**: Requires local security policy modifications
- **Group Policy Conflicts**: Domain-joined systems may have Group Policy overriding local settings
- **Service Dependencies**: Disabling services may affect applications - test thoroughly
- **Legacy Application Compatibility**: Some hardening measures (SMBv1 removal, NTLMv2 enforcement) may break legacy systems

## Troubleshooting

### Script Won't Run
```powershell
# Check execution policy
Get-ExecutionPolicy

# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Permission Denied
- Ensure you're running PowerShell as Administrator
- Check that your account has permission to modify security settings

### Remediation Script Not Generated
- Verify you used the `-ExportRemediation` parameter
- Check the script directory for files matching `CIS_Remediation_*.ps1`

### Some Remediations Fail
- Check if Group Policy is enforcing conflicting settings (domain-joined systems)
- Review the error messages in the remediation script output
- Some settings may require additional prerequisites

## Testing Recommendations

For VM environments:
1. Take a snapshot before running remediation
2. Run assessment (baseline)
3. Run remediation script
4. Reboot
5. Run assessment again (verify)
6. Compare results
7. Rollback snapshot if needed
8. Iterate and refine

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Areas for Enhancement
- Additional CIS controls
- Support for Windows 10/11 workstations
- Integration with configuration management tools
- Custom control definitions
- Compliance trend tracking

## Disclaimer

This tool is provided as-is for security assessment and hardening purposes. Always:
- Test in non-production environments first
- Review all changes before applying
- Maintain backups
- Understand the impact of each control
- Ensure changes align with your organization's security policies

The authors are not responsible for any system issues, downtime, or data loss resulting from the use of this tool.

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Version History

### v1.0.0 (2025-10-20)
- Initial release
- 51 essential CIS controls
- HTML report generation
- Automated remediation script export
- Support for Windows Server 2016/2019/2022

## Author

Created for Windows Server security hardening and CIS compliance assessment.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.
