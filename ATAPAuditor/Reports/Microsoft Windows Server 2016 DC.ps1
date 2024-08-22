
[Report] @{
	Title = "Windows Server 2016 Audit Report for Domain Controller"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark, Version: 2.0.0, Date: 2023-04-14"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
		"FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
	)
	Sections = @(
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
