[Report] @{
	Title = 'Internet Explorer 11 Audit Report'
	ModuleName = 'ATAPAuditor'
	BasedOn = @(
		'CIS Microsoft Internet Explorer 11 Benchmark, Version: 1.0.0, Date: 2014-12-01'
		'DISA Microsoft Internet Explorer 11 Security Technical Implementation Guide, Version: V1R15, Date: 2018-06-08'
		'Windows 10 Windows Server v2004 Security Baseline FINAL, Version: 2004, Date: 2020-08-04'
	)
	Sections = @(
		[ReportSection] @{
			Title = "CIS Recommendations"
			Description = "This section contains all CIS recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Internet Explorer 10-CIS-1.1.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = 'Advanced Audit Policy Configuration'
					AuditInfos = Test-AuditGroup "Microsoft Internet Explorer 10-CIS-1.1.0#AuditPolicies"
				}
				[ReportSection] @{
					Title = 'User Rights Assignment'
					AuditInfos = Test-AuditGroup "Microsoft Internet Explorer 10-CIS-1.1.0#UserRights"
				}
			)
		}
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all DISA recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Internet Explorer 11-DISA-V1R16#RegistrySettings"
				}
			)
		}
		[ReportSection] @{
			Title = "MS Recommendations"
			Description = "This section contains all MS baseline recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Internet Explorer 11-MS-2004#RegistrySettings"
				}
			)
		}
	)
}
