[Report] @{
	Title = "Ubuntu 20.04 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Ubuntu Linux 20.04"
		"Security baseline for Ubuntu"	
    )
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'CIS Test'
					AuditInfos = Test-AuditGroup "Ubuntu Linux 20.04-1.0.0"
				}
			)
		}
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
