[Report] @{
	Title = "Windows 11 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14"
		"Security baseline for Microsoft Windows 11, Version: 20H2, Date: 2020-12-17"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
	)
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains all benchmarks from CIS"
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-1.0.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-1.0.0#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-1.0.0#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-1.0.0#AuditPolicies"
				}
				[ReportSection] @{
					Title = 'Security Options'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-1.0.0#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = "Microsoft Benchmarks"
			Description = "This section contains all benchmarks from Microsoft"
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#AuditPolicies"
				}
				[ReportSection] @{
					Title = 'Security Options'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#SecurityOptions"
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
					Title = 'Enhanced security settings'
					AuditInfos = Test-AuditGroup "Enhanced security settings-FBPro-1.0#UserRights"
				}
			)
		}
	)
}
