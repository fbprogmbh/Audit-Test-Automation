[Report] @{
	Title = "Windows 11 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"Security baseline for Microsoft Windows 11, Version: 20H2, Date: 2020-12-17"	
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
		[ReportSection] @{
			Title = "Microsoft Benchmarks"
			Description = "This section contains all benchmarks from Microsoft"
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-2022#AuditPolicies"
				}
			)
		}
	)
}
