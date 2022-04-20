[Report] @{
	Title = "Windows 10 GDPR Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		'Bundesamt für Sicherheit in der Informationstechnik (BSI), Version: V1.1, Date: 2019-07-31'
		'GDPR settings by Microsoft, Version: 16082019, Date: 2019-08-16'
	)
	Sections = @(
		[ReportSection] @{
			Title = "BSI Recommendations"
			Description = "This section contains the Telemetry-Recommendations of the Federal Office for Information Security (BSI)"
			SubSections = @(
				[ReportSection] @{
					Title = "Telemetry"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 GDPR-BSI-V1.1#RegistrySettings"
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
	)
}
