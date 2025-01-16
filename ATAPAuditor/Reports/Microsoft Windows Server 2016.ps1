
[Report] @{
	Title = "Windows Server 2016 Audit Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"DISA Windows Server 2016 Security Technical Implementation Guide, Version: 1.12, Date: 2020-06-17"
		"CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark, Version: 3.0.0, Date: 2024-04-19"
		"Microsoft Security baseline for Windows Server 2016, Version: FINAL, Date 2016-10-17"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.2.1, Date: 2023-11-03"
		"FB Pro recommendations 'Enhanced settings', Version 1.2.1, Date: 2023-11-03"
	)
	Sections = @(
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all recommendations from the Windows Server 2016 Security Technical Implementation Guide V1R5 2018-07-27"
			SubSections = @(
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-DISA-1.12#AccountPolicies"
				},
				[ReportSection] @{
					Title = "Security Options"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-DISA-1.12#SecurityOptions"
				},
				[ReportSection] @{
					Title = "Registry Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-DISA-1.12#RegistrySettings"
				},
				[ReportSection] @{
					Title = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-DISA-1.12#AuditPolicies"
				}
				[ReportSection] @{
					Title = "Security Options"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-DISA-1.12#SecurityOptions"
				}
				#,
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
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-3.0.0#AccountPolicies"
				}
				[ReportSection] @{
					Title = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-3.0.0#AuditPolicies"
				}
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-3.0.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = "Security Options"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-3.0.0#SecurityOptions"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-CIS-3.0.0#UserRights"
				}
			)
		}
		[ReportSection] @{
			Title = "Microsoft Benchmarks"
			Description = "This section contains all benchmarks from Microsoft Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.2.0 - 14-05-2020. WARNING: Tests in this version haven't been fully tested yet."
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-Microsoft-FINAL#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-Microsoft-FINAL#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-Microsoft-FINAL#AccountPolicies"
				}
				[ReportSection] @{
					Title = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2016-Microsoft-FINAL#AuditPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = 'FB Pro recommendations'
			Description = 'This section contains the FB Pro recommendations.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Ciphers Suites and Hashes'
					AuditInfos = Test-AuditGroup "CiphersProtocolsHashesBenchmark-FBPro-1.2.1#RegistrySettings"
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
