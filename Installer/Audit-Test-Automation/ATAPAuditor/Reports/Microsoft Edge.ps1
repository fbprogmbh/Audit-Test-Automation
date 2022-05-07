[Report] @{
	Title = 'Microsoft Edge Report'
	ModuleName = 'ATAPAuditor'
	BasedOn = @(
		"Microsoft Edge v85 Security Baseline FINAL, Version: 85, Date: 2020-08-27"
	)
	Sections = @(
		[ReportSection] @{
			Title = "MS Baseline"
			Description = "This section contains all MS baseline recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Edge-MS-85#RegistrySettings"
				}
			)
		}
	)
}
