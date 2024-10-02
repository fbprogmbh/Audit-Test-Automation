[Report] @{
	Title = "Red Hat Enterprise Linux 9"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Red Hat Enterprise Linux 9 version 1.0.0"
    )
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'CIS Red Hat Enterprise Linux 9'
					AuditInfos = Test-AuditGroup "Red Hat Enterprise Linux 9-CIS-1.0.0"
				}
			)
		}
	)
}
