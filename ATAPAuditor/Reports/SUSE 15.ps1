[Report] @{
	Title = "SUSE Enterprise 15"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS SUSE Linux 15 version 1.1.1"
    )
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'CIS SUSE Linux 15'
					AuditInfos = Test-AuditGroup "SUSE Linux 15-CIS-1.1.1"
				}
			)
		}
	)
}
