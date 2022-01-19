
[Report] @{
	Title = "Windows Server 2019 Audit Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
        "Windows Server 2019 Security Technical Implementation Guide, Version: V1R2, Date: 2020-01-24"
		"CIS Microsoft Windows Server 2019 Benchmark, Version: 1.1.0, Date: 2020-01-10"
		"Microsoft Security baseline for Windows Server 2019, Version: FINAL, Date 2019-06-18"
	)
	Sections = @(
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all recommendations from DISA"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-DISA-V1R2#RegistrySettings"
				},
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-DISA-V1R2#UserRights"
				},
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-DISA-V1R2#AccountPolicies"
				},
				[ReportSection] @{
					Title = "Windows Features"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-DISA-V1R2#WindowsFeatures"
				},
				[ReportSection] @{
					Title = "File System Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-DISA-V1R2#FileSystemPermissions"
				},
				[ReportSection] @{
					Title = "Registry Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-DISA-V1R2#RegistryPermissions"
				}
			)
		}
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains all benchmarks from CIS"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-CIS-1.2.1#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-CIS-1.2.1#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-CIS-1.2.1#AccountPolicies"
				}
				# [ReportSection] @{
				# 	Title = "Windows Firewall with Advanced Security"
				# 	AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-CIS-1.1.0#FirewallProfileSettings"
				# }
				[ReportSection] @{
					Title = " Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-CIS-1.2.1#AuditPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = "Microsoft Benchmarks"
			Description = "This section contains all benchmarks from Microsoft"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-Microsoft-FINAL#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-Microsoft-FINAL#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-Microsoft-FINAL#AccountPolicies"
				}
				[ReportSection] @{
					Title = " Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2019-Microsoft-FINAL#AuditPolicies"
				}
			)
		}
	)
}
