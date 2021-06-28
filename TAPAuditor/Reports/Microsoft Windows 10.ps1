[Report] @{
	Title = "Windows 10 Report"
	ModuleName = "TAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows 10 Enterprise Release 2004 Benchmark, Version: 1.9.0, Date: 2020-08-14"
		"CIS Microsoft Office 2016 Benchmark, Version: 1.1.0, Date: 2016-11-08"
		"Microsoft Security baseline (FINAL) for Windows 10, Version: 20H2, Date: 2020-12-17"
		"SiSyPHuS Windows - Telemetry components - Bundesamt fuer Sicherheit in der Informationstechnik (BSI), Version: V1.1, Date: 2019-07-31"
		"BSI SiM-08202 Client unter Windows 10, Version: 1, Date: 2017-09-13"
	)
	Sections = @(
		[ReportSection] @{
			Title = 'CIS Benchmarks'
			Description = 'This section contains all benchmarks from CIS.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Windows 10'
					Description = 'This section contains the CIS "Windows 10" Benchmark results.'
					SubSections = @(
						[ReportSection] @{
							Title = 'Registry Settings/Group Policies'
							AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.9.0#RegistrySettings"
						}
						[ReportSection] @{
							Title = 'User Rights Assignment'
							AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.9.0#UserRights"
						}
						[ReportSection] @{
							Title = 'Account Policies'
							AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.9.0#AccountPolicies"
						}
						[ReportSection] @{
							Title = 'Advanced Audit Policy Configuration'
							AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.9.0#AuditPolicies"
						}
					)
				}
				[ReportSection] @{
					Title = 'Office 2016'
					Description = 'This section contains the CIS "Office 2016" Benchmark results.'
					SubSections = @(
						[ReportSection] @{
							Title = 'Microsoft Office 2016'
							AuditInfos = Test-AuditGroup "Microsoft Office 2016-CIS-1.1.0#RegistrySettings"
						}
					)
				}
			)
		}
		[ReportSection] @{
			Title = 'Microsoft Benchmarks'
			Description = 'This section contains all benchmarks from Microsoft.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-20H2#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-20H2#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-20H2#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-20H2#AuditPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = "BSI Recommendations"
			Description = "This section contains the Telemetry-Recommendations of the Federal Office for Information Security (BSI)"
			SubSections = @(
				[ReportSection] @{
					Title = "Telemetry"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 GDPR-BSI-V1.1#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks'
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
