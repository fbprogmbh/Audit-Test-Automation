[Report] @{
	Title = "Windows 10 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
		"DISA Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
		"CYBERGOVAU Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2020, Date 2020-10-01"
		"Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
		"BSI SiM-08202 Client unter Windows 10, Version: 1, Date: 2017-09-13"
        "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
	)
	Sections = @(
		[ReportSection] @{
			Title = 'CIS Benchmarks'
			Description = 'This section contains the CIS Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.12.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.12.0#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.12.0#AccountPolicies"
				}
				# [ReportSection] @{
				# 	Title = 'Windows Firewall with Advanced Security'
				# 	AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.8.1#FirewallProfileSettings"
				# }
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-1.12.0#AuditPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains the DISA STIG results."
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#AccountPolicies"
				}
				[ReportSection] @{
					Title = "Windows Features"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#WindowsOptionalFeatures"
				}
				[ReportSection] @{
					Title = "File System Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#FileSystemPermissions"
				}
				[ReportSection] @{
					Title = "Registry Permissions"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R16#RegistryPermissions"
				}
			)
		}
		[ReportSection] @{
			Title = 'CyberGovAu Benchmarks'
			Description = 'This section contains the CyberGovAu Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CyberGovAu-10.2020#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CyberGovAu-10.2020#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CyberGovAu-10.2020#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CyberGovAu-10.2020#AuditPolicies"
				}
			)
		}
		[ReportSection] @{
			Title = 'Microsoft Benchmarks'
			Description = 'This section contains the Microsoft Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-21H1#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-21H1#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-21H1#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-21H1#AuditPolicies"
				}
			)
		}
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
		# TODO: Will be removed with version 5.3, if no crucial changes are necessary on these AuditGroups
		# [ReportSection] @{
		# 	Title = 'BSI Benchmarks BPOL'
		# 	Description = 'This section contains the BSI Benchmark BPOL results.'
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
		# 		# [ReportSection] @{
		# 		# 	Title = 'Security Options'
		# 		# 	AuditInfos = Test-AuditGroup "Microsoft Windows 10 BSI BPOL#SecurityOptions"
		# 		# }
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
		[ReportSection] @{
			Title = 'BSI Benchmarks SiSyPHus-BSI Bundespolizei'
			Description = 'This section contains the BSI Benchmark results.'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-BSI-Bundespolizei#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-BSI-Bundespolizei#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-BSI-Bundespolizei#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-BSI-Bundespolizei#AuditPolicies"
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
					Title = 'Enhanced security settings'
					AuditInfos = Test-AuditGroup "Enhanced security settings-FBPro-1.0#UserRights"
				}
			)
		}
	)
}
