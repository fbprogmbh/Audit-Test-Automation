[Report] @{
	Title = "Rocky Linux 9"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Rocky Linux 9 version 2.0.0"
    )
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'Rocky Linux 9'
					AuditInfos = Test-AuditGroup "Rocky Linux 9-CIS-2.0.0"
				}
			)
		}
	)
}
