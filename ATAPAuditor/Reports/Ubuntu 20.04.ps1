[Report] @{
	Title = "Ubuntu 20.04 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Ubuntu Linux 20.04 version 1.1.0"
    )
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'CIS Ubuntu Linux 20.04'
					AuditInfos = Test-AuditGroup "Ubuntu Linux 20.04-CIS-1.1.0"
				}
			)
		}
	)
}
