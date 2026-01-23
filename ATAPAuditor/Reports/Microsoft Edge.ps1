[Report] @{
	Title = 'Microsoft Edge Report'
	ModuleName = 'ATAPAuditor'
	BasedOn = @(
		"CIS Microsoft Edge Benchmark, Version: 4.0.0, Date: 2025-10-27"
		"Microsoft Edge v117 Security Baseline FINAL, Version: 117, Date: 2024-04-12"
	)
	Sections = @(
		[ReportSection] @{
			Title = 'CIS Benchmarks'
			Description = "This section contains all CIS recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Edge-CIS-4.0.0#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = "MS Baseline"
			Description = "This section contains all Microsoft recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Edge-Microsoft-117#RegistrySettings"
				}
			)
		}
	)
}
