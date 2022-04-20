[Report] @{
	Title = "Ubuntu 20.04 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"Security baseline for Ubuntu"	
    )
	Sections = @(
		[ReportSection] @{
			Title = "General Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'Security Base Data'
					AuditInfos = Test-AuditGroup "Linux Security Base Data"
				}
			)
		}
	)
}
