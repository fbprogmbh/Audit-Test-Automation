[Report] @{
	Title = "Ubuntu 22.04 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Ubuntu Linux 22.04 version 2.0.0"
    )
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'CIS Ubuntu Linux 22.04'
					AuditInfos = Test-AuditGroup "Ubuntu Linux 22.04-CIS-2.0.0"
				}
			)
		}
	)
}
