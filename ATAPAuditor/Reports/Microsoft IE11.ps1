[Report] @{
	Title = 'Internet Explorer 11 Audit Report'
	ModuleName = 'ATAPAuditor'
	BasedOn = @(
		'CIS Microsoft Internet Explorer 11 Benchmark, Version: 1.0.0, Date: 2014-12-01'
		'DISA Microsoft Internet Explorer 11 Security Technical Implementation Guide, Version: V1R15, Date: 2018-06-08'
	)
	Sections = @(
		[ReportSection] @{
			Title = "CIS Recommendations"
			Description = "This section contains all CIS recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft IE11-CIS-1.0.0#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all DISA recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft IE11-DISA-V1R16#RegistrySettings"
				}
			)
		}
	)
}
