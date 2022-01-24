[Report] @{
	Title = "Windows Security Base Data Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"Security baseline for Microsoft Windows"	
    )
	Sections = @(
		[ReportSection] @{
			Title = "General Benchmarks"
			Description = "This section contains general benchmarks"
			SubSections = @(
				[ReportSection] @{
					Title = 'Security Base Data'
					AuditInfos = Test-AuditGroup "Microsoft Windows Security Base Data"
				}
			)
		}
	)
}
