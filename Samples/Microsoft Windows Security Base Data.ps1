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
					Description = "This section contains basic recommendations for a secure Microsoft Windows configuration."
					AuditInfos = Test-AuditGroup "Microsoft Windows Security Base Data"
				}
			)
		}
	)
}
