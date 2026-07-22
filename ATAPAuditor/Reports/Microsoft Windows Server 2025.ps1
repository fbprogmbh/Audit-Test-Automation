
[Report] @{
	Title      = "Windows Server 2025 Audit Report"
	ModuleName = "ATAPAuditor"
	BasedOn    = @(
		"CIS Microsoft Windows Server 2025, Version: 1.0.0, Date 2025-03-19"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.2.2, Date: 2026-03-17"
		"FB Pro recommendations 'Enhanced settings', Version 1.2.2, Date: 2023-11-03"
	)
	Sections   = @(
		[ReportSection] @{
			Title       = "CIS Benchmarks"
			Description = "This section contains all CIS recommendations"
			SubSections = @(
				[ReportSection] @{
					Title      = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2025-CIS-1.0.0#RegistrySettings"
				}
				[ReportSection] @{
					Title      = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2025-CIS-1.0.0#UserRights"
				}
				[ReportSection] @{
					Title      = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2025-CIS-1.0.0#AccountPolicies"
				}
				[ReportSection] @{
					Title      = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2025-CIS-1.0.0#AuditPolicies"
				}
				[ReportSection] @{
					Title      = "Security Options"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2025-CIS-1.0.0#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title       = 'FB Pro recommendations'
			Description = "This section contains all FB Pro recommendations"
			SubSections = @(
				[ReportSection] @{
					Title      = 'Ciphers Suites and Hashes'
					AuditInfos = Test-AuditGroup "Microsoft Windows CiphersProtocolsHashesBenchmark-FB Pro GmbH-1.2.2#RegistrySettings"
				}
				[ReportSection] @{
					Title      = 'Enhanced security settings - Registry Settings'
					AuditInfos = Test-AuditGroup "Microsoft Windows Enhanced Security Settings-FB Pro GmbH-1.2.2#RegistrySettings"
				}
				[ReportSection] @{
					Title      = 'Enhanced security settings - User Rights'
					AuditInfos = Test-AuditGroup "Microsoft Windows Enhanced Security Settings-FB Pro GmbH-1.2.2#UserRights"
				}
			)
		}
	)
}