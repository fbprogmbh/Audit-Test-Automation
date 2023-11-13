[Report] @{
	Title = "Fedora 35 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"Security baseline for Fedora"	
    )
	Sections = @(
		[ReportSection] @{
			Title = "General Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'Security Base Data'
					AuditInfos = Test-AuditGroup "SBD - Linux Base Security"
				}
			)
		}
	)
}
