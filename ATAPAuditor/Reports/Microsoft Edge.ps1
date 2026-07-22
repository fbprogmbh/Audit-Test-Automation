[Report] @{
	Title = 'Microsoft Edge Report'
	ModuleName = 'ATAPAuditor'
	BasedOn = @(
		"CIS Microsoft Edge Benchmark, Version: 4.0.0, Date: 2025-10-27"
		"Microsoft Edge v148 Security Baseline, Version: 148, Date: 2026-05-19"
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
					AuditInfos = Test-AuditGroup "Microsoft Edge-Microsoft-148#RegistrySettings"
				}
			)
		}
	)
}
