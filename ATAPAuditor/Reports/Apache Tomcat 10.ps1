[Report] @{
	Title = "Apache Tomcat 10"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Apache Tomcat 1.1.0"
    )
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains the general benchmark results"
			SubSections = @(
				[ReportSection] @{
					Title = 'CIS Apache Tomcat 10'
					AuditInfos = Test-AuditGroup "Apache Tomcat-10-CIS-1.1.0"
				}
			)
		}
	)
}
