[Report] @{
	Title = 'Microsoft PowerPoint 2016 Audit Report'
	ModuleName = 'ATAPAuditor'
	AuditorVersion = '4.8'
	BasedOn = 'DISA Microsoft Powerpoint 2016 Security Technical Implementation Guide, Version: V1R1, Date: 2016-11-14'
	Sections = @(
		[ReportSection] @{
			Title = "DISA Recommendations"
			Description = "This section contains all DISA recommendations"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Office 2016 PowerPoint-DISA-V1R1#RegistrySettings"
				}
			)
		}
	)
}
