[Report] @{
	Title = 'Microsoft Edge Report'
	ModuleName = 'ATAPAuditor'
	BasedOn = @(
		"Microsoft Edge v99 Security Baseline FINAL, Version: 99, Date: 2022-03-07"
		"CIS Microsoft Edge Benchmark, Version: 2.0.0, Date: 2023-09-21"
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
					AuditInfos = Test-AuditGroup "Microsoft Edge-CIS-2.0.0#RegistrySettings"
				}
			)
		}
	)
}
