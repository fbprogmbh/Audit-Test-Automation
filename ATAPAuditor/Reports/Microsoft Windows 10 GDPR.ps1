[Report] @{
	Title = "Windows 10 GDPR Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		'Bundesamt für Sicherheit in der Informationstechnik (BSI), Version: V1.2, Date: 2020-04-27'
		'GDPR settings by Microsoft, Version: 16082019, Date: 2019-08-16'
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
		"FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
	)
	Sections = @(
		[ReportSection] @{
			Title = "BSI Recommendations"
			Description = "This section contains the Telemetry-Recommendations of the Federal Office for Information Security (BSI)"
			SubSections = @(
				[ReportSection] @{
					Title = "Telemetry"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHus-Telemetrie-BSI-V1.2#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = "Data Protection Microsoft"
			Description = "This section contains all benchmarks given by Microsoft to be GDPR compliant"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 GDPR-MS-16082019#RegistrySettings"
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
