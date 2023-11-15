[Report] @{
	Title = "Debian 11 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Debian 11, Version: 1.0.0, Date: 2022-09-22"
    )
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains all benchmarks from CIS"
			SubSections = @(
				[ReportSection] @{
					Title = 'CIS Recommendations'
					AuditInfos = Test-AuditGroup "Debian Linux 11-CIS-1.0.0"
				}
			)
		}
	)
}
