[Report] @{
	Title = 'Microsoft Outlook 2016 Audit Report'
	ModuleName = 'ATAPAuditor'
	BasedOn = 'DISA Microsoft Outlook 2016 Security Technical Implementation Guide, Version: V1R2, Date: 2017-07-28'
	Sections = @(
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all DISA recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Office 2016 Outlook-DISA-V1R2#RegistrySettings"
				}
			)
		}
	)
}
