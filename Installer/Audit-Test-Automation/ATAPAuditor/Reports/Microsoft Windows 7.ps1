[Report] @{
	Title = "Windows 7 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows 7 Workstation Benchmark, Version: 3.1.0, Date: 2018-03-02"
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
			Title = 'CIS Benchmarks'
			Description = 'This section contains the CIS Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 7-CIS-3.1.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 7-CIS-3.1.0#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 7-CIS-3.1.0#AuditPolicies"
				}
			)
		}
	)
}
