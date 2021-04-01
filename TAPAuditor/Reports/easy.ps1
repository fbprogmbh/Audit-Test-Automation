[Report] @{
	Title = "Windows 10 Report"
	ModuleName = "THCAuditor"
	BasedOn = @(
		"CIS Microsoft Windows 10 Enterprise Release 2004 Benchmark, Version: 1.9.0, Date: 2020-08-14"
		"Microsoft Security baseline (FINAL) for Windows 10, Version: 20H2, Date: 2020-12-17"
		"SiSyPHuS Windows - Telemetry components - Bundesamt für Sicherheit in der Informationstechnik (BSI), Version: V1.1, Date: 2019-07-31"
	)
	Sections = @(
		[ReportSection] @{
					Title = 'Office 2016'
					Description = 'This section contains the CIS Benchmark results.'
					SubSections = @(
						[ReportSection] @{
							Title = 'Microsoft Office 2016'
							AuditInfos = Test-AuditGroup "Microsoft Office 2016-CIS-1.1.0#RegistrySettings"
						}
					)
					}
	)
}
