﻿[Report] @{
	Title = "Windows 10 Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows 10 Enterprise, Version: 3.0.0, Date: 2024-02-22"
		"Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
		"BSI Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
		"BSI SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2020-04-27"
		"DISA Windows 10 Security Technical Implementation Guide, Version: V1R23, Date: 2019-10-25"
		"ACSC Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2021, Date 2021-10-01"
		"FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.2.1, Date: 2023-11-03"
		"FB Pro recommendations 'Enhanced settings', Version 1.2.1, Date: 2023-11-03"
	)
	Sections = @(
		[ReportSection] @{
			Title = 'CIS Benchmarks'
			Description = "This section contains all CIS recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-3.0.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-3.0.0#UserRights"
				}
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-3.0.0#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-3.0.0#AuditPolicies"
				}
				[ReportSection] @{
					Title = 'Security Options'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-CIS-3.0.0#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = 'Microsoft Benchmarks'
			Description = "This section contains all Microsoft recommendations"
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
				[ReportSection] @{
					Title = 'Security Options'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-Microsoft-21H1#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks SiSyPHuS Logging'
			Description = 'This section contains all BSI logging recommendations'
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
				Description = 'This section contains all BSI HD recommendations'
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
		}
		[ReportSection] @{
			Title = 'BSI Benchmarks SiSyPHus-BSI Telemetrie'
			Description = 'This section contains all BSI telemetry recommendations'
			SubSections = @(
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10 SiSyPHus-Telemetrie-BSI-V1.2#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all DISA recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R23#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R23#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R23#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R23#AuditPolicies"
				}
				[ReportSection] @{
					Title = 'Security Options'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-DISA-V1R23#SecurityOptions"
				}
			)
		}
		[ReportSection] @{
			Title = 'ACSC Benchmarks'
			Description = "This section contains all ACSC recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = 'Account Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-ACSC-21H1#AccountPolicies"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-ACSC-21H1#AuditPolicies"
				}
				[ReportSection] @{
					Title = 'Registry Settings/Group Policies'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-ACSC-21H1#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-ACSC-21H1#SecurityOptions"
				}
				[ReportSection] @{
					Title = 'Security Options'
					AuditInfos = Test-AuditGroup "Microsoft Windows 10-ACSC-21H1#UserRights"
				}
			)
		}
		[ReportSection] @{
			Title = 'FB Pro recommendations'
			Description = "This section contains all FB Pro recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = 'Ciphers Suites and Hashes'
					AuditInfos = Test-AuditGroup "CiphersProtocolsHashesBenchmark-FBPro-1.2.1#RegistrySettings"
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
