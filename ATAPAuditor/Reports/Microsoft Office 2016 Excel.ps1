[Report] @{
	Title = 'Microsoft Excel 2016 Audit Report'
	ModuleName = 'ATAPAuditor'
	AuditorVersion = '4.8'
	BasedOn = 'DISA Microsoft Excel 2016 Security Technical Implementation Guide, Version: V1R2, Date: 2017-10-27'
	Sections = @(
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all DISA recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Office 2016 Excel-DISA-V1R2#RegistrySettings"
				}
			)
		}
	)
}
