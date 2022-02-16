
[Report] @{
	Title = "Windows Server 2022 Audit Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"Security baseline for Microsoft Windows Server 2022, Version: FINAL, Date 2021-09-27"
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
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022 Domain Controller-Microsoft-2022#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022 Domain Controller-Microsoft-2022#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022 Domain Controller-Microsoft-2022#AccountPolicies"
				}
				[ReportSection] @{
					Title = " Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2022 Domain Controller-Microsoft-2022#AuditPolicies"
				}
			)
		}
	)
}
