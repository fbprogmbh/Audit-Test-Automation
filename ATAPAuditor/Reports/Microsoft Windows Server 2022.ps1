
[Report] @{
	Title = "Windows Server 2022 Audit Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows Server 2022, Version: 3.0.0, Date 2023-04-14"
		"Microsoft Security baseline for Microsoft Windows Server 2022, Version: FINAL, Date 2021-09-27"
		"DISA Windows Server 2022, Version: V1R1, Date 2022-09-28"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.2.1, Date: 2023-11-03"
		"FB Pro recommendations 'Enhanced settings', Version 1.2.1, Date: 2023-11-03"
	)
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains all CIS recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-CIS-3.0.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-CIS-3.0.0#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-CIS-3.0.0#AccountPolicies"
				}
				[ReportSection] @{
					Title = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-CIS-3.0.0#AuditPolicies"
				}
				[ReportSection] @{
					Title = "Security Options"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-CIS-3.0.0#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = "Microsoft Benchmarks"
			Description = "This section contains all Microsoft recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-Microsoft-FINAL#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-Microsoft-FINAL#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-Microsoft-FINAL#AccountPolicies"
				}
				[ReportSection] @{
					Title = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-Microsoft-FINAL#AuditPolicies"
				}
				[ReportSection] @{
					Title = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-Microsoft-FINAL#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = "DISA Benchmarks"
			Description = "This section contains all DISA recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-DISA-V1R1#RegistrySettings"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-DISA-V1R1#AccountPolicies"
				}
				[ReportSection] @{
					Title = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-DISA-V1R1#AuditPolicies"
				}
				[ReportSection] @{
					Title = "Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022-DISA-V1R1#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = 'FB Pro recommendations'
			Description = "This section contains all FB Pro recommendations"
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
