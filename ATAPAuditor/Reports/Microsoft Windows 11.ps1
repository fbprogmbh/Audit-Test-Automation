[Report] @{
	Title = "Windows 11 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows 11 Enterprise 3.0.0 Benchmark, Version: 3.0.0, Date: 2024-02-22"
		"Security baseline for Microsoft Windows 11, Version: 22H2, Date: 2022-09-20"
		"Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
		"SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2019-07-31"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
		"FB Pro recommendations 'Enhanced settings', Version 1.2.1, Date: 2023-11-03"
	)
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains all benchmarks from CIS"
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-3.0.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-3.0.0#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-3.0.0#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-3.0.0#AuditPolicies"
				}
				[ReportSection] @{
					Title = 'Security Options'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-CIS-3.0.0#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = "Microsoft Benchmarks"
			Description = "This section contains all benchmarks from Microsoft"
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-22H2#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-22H2#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-22H2#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-22H2#AuditPolicies"
				}
				[ReportSection] @{
					Title = 'Security Options'
					AuditInfos = Test-AuditGroup "Microsoft Windows 11-Microsoft-22H2#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks SiSyPHuS Logging'
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
		try {
			# Get domain role
			# 0 {"Standalone Workstation"}
			# 1 {"Member Workstation"}
			# 2 {"Standalone Server"}
			# 3 {"Member Server"}
			# 4 {"Backup Domain Controller"}
			# 5 {"Primary Domain Controller"}
			$domainRole = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole
		} catch {
			$domainRole = 99
		}
		# if system is Member Workstation	
		if ($domainRole -eq 1) {
			[ReportSection] @{
				Title = 'BSI Benchmarks SiSyPHuS HD'
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
					[ReportSection] @{
						Title = 'Security Options'
						AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS HD-BSI-1.3#SecurityOptions"
					}
				)
			}
		} else {
			[ReportSection] @{
				Title = 'BSI Benchmarks SiSyPHuS NE'
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
					[ReportSection] @{
						Title = 'Security Options'
						AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS NE-BSI-1.3#SecurityOptions"
					}
				)
			}
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks SiSyPHus-BSI'
			Description = 'This section contains the BSI Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHus-Telemetrie-BSI-V1.2#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = 'FB Pro recommendations'
			Description = 'This section contains the FB Pro recommendations.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Ciphers Suites and Hashes'
					AuditInfos = Test-AuditGroup "CiphersProtocolsHashesBenchmark-FBPro-1.1.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'Enhanced security settings - Registry Settings'
					AuditInfos = Test-AuditGroup "Microsoft Windows Enhanced Security Settings-FB Pro GmbH-1.2.1#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'Enhanced security settings - User Rights'
					AuditInfos = Test-AuditGroup "Microsoft Windows Enhanced Security Settings-FB Pro GmbH-1.2.1#UserRights"
				}
			)
		}
	)
}
