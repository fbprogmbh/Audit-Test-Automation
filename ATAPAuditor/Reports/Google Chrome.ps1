[Report] @{
	Title = 'Google Chrome Audit Report'
	ModuleName = 'ATAPAuditor'
	AuditorVersion = '4.8'
	BasedOn = @(
		"CIS Google Chrome Benchmark, Version: 2.0.0, Date: 2019-05-17"
		"DISA Google Chrome Security Technical Implementation Guide, Version: V1R15, Date: 2019-01-28"
	)
	Sections = @(
		[ReportSection] @{
			Title = "CIS Recommendations"
			Description = "This section contains all CIS recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Google Chrome-CIS-2.0.0#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all DISA recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Google Chrome-DISA-V1R15#RegistrySettings"
				}
			)
		}
	)
}
