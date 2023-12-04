[Report] @{
	Title = "Red Hat Enterprise Linux 8 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"Security baseline for Red Hat Enterprise Linux"	
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
