
[Report] @{
	Title = "Windows Server 2016 Audit Report for Domain Controller"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"DISA Windows Server 2016 Security Technical Implementation Guide, Version: V1R6, Date: 2018-10-26"
		"CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark, Version: 2.0.0, Date: 2023-04-14"
		"Microsoft Security baseline for Windows Server 2016 Domain Controller, Version: FINAL, Date 2016-10-17"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
		"FB Pro recommendations 'Enhanced settings', Version 1.2.1, Date: 2023-11-03"
	)
	Sections = @(
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all recommendations from the Windows Server 2016 Security Technical Implementation Guide V1R5 2018-07-27"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-DISA-V1R6#RegistrySettings"
				},
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-DISA-V1R6#UserRights"
				},
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-DISA-V1R6#AccountPolicies"
				},
				[ReportSection] @{
					Title = "Windows Features"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-DISA-V1R6#WindowsFeatures"
				},
				[ReportSection] @{
					Title = "File System Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-DISA-V1R6#FileSystemPermissions"
				},
				[ReportSection] @{
					Title = "Registry Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-DISA-V1R6#RegistryPermissions"
				}#,
				# [ReportSection] @{
				# 	Title = "Other"
				# 	AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-DISA-#Other"
				# }
			)
		}
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains all benchmarks from CIS Microsoft Windows Server 2016 RTM (Release 1607)"
			SubSections = @(
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-2.0.0#AccountPolicies"
				}
				[ReportSection] @{
					Title = " Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-2.0.0#AuditPolicies"
				}
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-2.0.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = "Security Options"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-2.0.0#SecurityOptions"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-2.0.0#UserRights"
				}
			)
		}
		[ReportSection] @{
			Title = "Microsoft Benchmarks"
			Description = "This section contains all benchmarks from Microsoft Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.2.0 - 14-05-2020. WARNING: Tests in this version haven't been fully tested yet."
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-Microsoft-FINAL#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-Microsoft-FINAL#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-Microsoft-FINAL#AccountPolicies"
				}
				[ReportSection] @{
					Title = " Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016 Domain Controller-Microsoft-FINAL#AuditPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = 'FB Pro recommendations'
			Description = 'This section contains the FB Pro recommendations.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Ciphers Suites and Hashes'
					AuditInfos = Test-AuditGroup "CiphersProtocolsHashesBenchmark-FBPro-1.1.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'Enhanced security settings - Registry Settings'
					AuditInfos = Test-AuditGroup "Microsoft Windows Enhanced Security Settings-FB Pro GmbH-1.2.1#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'Enhanced security settings - User Rights'
					AuditInfos = Test-AuditGroup "Microsoft Windows Enhanced Security Settings-FB Pro GmbH-1.2.1#UserRights"
				}
			)
		}
	)
}
