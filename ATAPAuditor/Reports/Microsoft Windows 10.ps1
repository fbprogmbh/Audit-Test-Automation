[Report] @{
	Title = "Windows 10 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows 10 Enterprise Release 1909 Benchmark, Version: 1.8.1, Date: 2020-01-28"
		"Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
	)
	Sections = @(
		[ReportSection] @{
			Title = 'CIS Benchmarks'
			Description = 'This section contains the CIS Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.8.1#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.8.1#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.8.1#AccountPolicies"
				}
				# [ReportSection] @{
				# 	Title = 'Windows Firewall with Advanced Security'
				# 	AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.8.1#FirewallProfileSettings"
				# }
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.8.1#AuditPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains the DISA STIG results."
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#AccountPolicies"
				}
				[ReportSection] @{
					Title = "Windows Features"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#WindowsOptionalFeatures"
				}
				[ReportSection] @{
					Title = "File System Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#FileSystemPermissions"
				}
				[ReportSection] @{
					Title = "Registry Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#RegistryPermissions"
				}
			)
		}
	)
}
