[Report] @{
	Title = 'Microsoft Edge Report'
	ModuleName = 'ATAPAuditor'
	BasedOn = @(
		"Microsoft Edge v99 Security Baseline FINAL, Version: 99, Date: 2022-03-07"
		"CIS Microsoft Edge Benchmark, Version: 1.1.0, Date: 2022-09-19"
	)
	Sections = @(
		[ReportSection] @{
			Title = "MS Baseline"
			Description = "This section contains all MS baseline recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Edge-Microsoft-99#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = 'CIS Benchmarks'
			Description = 'This section contains the CIS Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Edge-CIS-1.1.0#RegistrySettings"
				}
			)
		}
	)
}
