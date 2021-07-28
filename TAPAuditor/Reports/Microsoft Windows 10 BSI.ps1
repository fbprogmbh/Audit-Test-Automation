[Report] @{
	Title = "Windows 10 BSI Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"BSI SiM-08202 Client unter Windows 10, Version: 1, Date: 2017-09-13"
        "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
	)
	Sections = @(
		[ReportSection] @{
			Title = 'BSI Benchmarks SySiPHuS Logging'
			Description = 'This section contains the BSI Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS Logging-BSI-1.3#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS Logging-BSI-1.3#AuditPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks SySiPHuS HD'
			Description = 'This section contains the BSI Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS HD-BSI-1.3#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS HD-BSI-1.3#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS HD-BSI-1.3#AccountPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks SySiPHuS ND'
			Description = 'This section contains the BSI Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS ND-BSI-1.3#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS ND-BSI-1.3#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS ND-BSI-1.3#AccountPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks SySiPHuS NE'
			Description = 'This section contains the BSI Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS NE-BSI-1.3#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS NE-BSI-1.3#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS NE-BSI-1.3#AccountPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks SiM-08202 - BPOL'
			Description = 'This section contains the BSI Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#AuditPolicies"
				}
			)
		}
	)
}
