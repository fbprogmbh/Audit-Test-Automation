[Report] @{
	Title = "Windows 10 BSI Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"BSI SiM-08202 Client unter Windows 10, Version: 1, Date: 2017-09-13"
        "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
		"SiSyPHuS Recommendations for Telemetry Components: Version 1.1, Date: 2019-07-31"
		"Sicherheitsmodul Richtlinie Bundespolizei SiM-08202: Version 1.0, Date: 2017-09-13"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
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
		# if system is Standalone Workstation
		if ($domainRole -eq 0) {
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
					[ReportSection] @{
						Title = 'Security Options'
						AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS NE-BSI-1.3#SecurityOptions"
					}
				)
			}	
		}
		# if system is Member Workstation	
		if ($domainRole -eq 1) {
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
					[ReportSection] @{
						Title = 'Security Options'
						AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS HD-BSI-1.3#SecurityOptions"
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
					[ReportSection] @{
						Title = 'Security Options'
						AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHuS ND-BSI-1.3#SecurityOptions"
					}
				)
			}
		}
		# [ReportSection] @{
		# 	Title = 'BSI Benchmarks SiM-08202 - BPOL'
		# 	Description = 'This section contains the BSI Benchmark results.'
		# 	SubSections = @(
		# 		[ReportSection] @{
		# 			Title = 'Registry Settings/Group Policies'
		# 			AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#RegistrySettings"
		# 		}
		# 		[ReportSection] @{
		# 			Title = 'User Rights Assignment'
		# 			AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#UserRights"
		# 		}
		# 		[ReportSection] @{
		# 			Title = 'Account Policies'
		# 			AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#AccountPolicies"
		# 		}
		# 		[ReportSection] @{
		# 			Title = 'Advanced Audit Policy Configuration'
		# 			AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#AuditPolicies"
		# 		}
		# 	)
		# }
		[ReportSection] @{
			Title = 'BSI Benchmarks SiSyPHus-BSI'
			Description = 'This section contains the BSI Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHus-BSI-V1.1#RegistrySettings"
				}
			)
		}
		# [ReportSection] @{
		# 	Title = 'BSI Benchmarks SiSyPHus-BSI Bundespolizei'
		# 	Description = 'This section contains the BSI Benchmark results.'
		# 	SubSections = @(
		# 		[ReportSection] @{
		# 			Title = 'Registry Settings/Group Policies'
		# 			AuditInfos = Test-AuditGroup "Microsoft Windows 10-BSI-Bundespolizei#RegistrySettings"
		# 		}
		# 		[ReportSection] @{
		# 			Title = 'User Rights Assignment'
		# 			AuditInfos = Test-AuditGroup "Microsoft Windows 10-BSI-Bundespolizei#UserRights"
		# 		}
		# 		[ReportSection] @{
		# 			Title = 'Account Policies'
		# 			AuditInfos = Test-AuditGroup "Microsoft Windows 10-BSI-Bundespolizei#AccountPolicies"
		# 		}
		# 		[ReportSection] @{
		# 			Title = 'Advanced Audit Policy Configuration'
		# 			AuditInfos = Test-AuditGroup "Microsoft Windows 10-BSI-Bundespolizei#AuditPolicies"
		# 		}
		# 	)
		# }
		[ReportSection] @{
			Title = 'FB Pro recommendations'
			Description = 'This section contains the FB Pro recommendations.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Ciphers Suites and Hashes'
					AuditInfos = Test-AuditGroup "CiphersProtocolsHashesBenchmark-FBPro-1.1.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'Enhanced security settings'
					AuditInfos = Test-AuditGroup "Enhanced security settings-FBPro-1.0#UserRights"
				}
			)
		}
	)
}
