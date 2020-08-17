[Report] @{
	Title = 'Microsoft Office 2016 Audit Report'
	ModuleName = 'ATAPAuditor'
	AuditorVersion = '4.8'
	BasedOn = @(
		'DISA Microsoft Excel 2016 Security Technical Implementation Guide, Version: V1R2, Date: 2017-10-27'
		'DISA Microsoft Outlook 2016 Security Technical Implementation Guide, Version: V1R2, Date: 2017-07-28'
		'DISA Microsoft Powerpoint 2016 Security Technical Implementation Guide, Version: V1R1, Date: 2016-11-14'
		'DISA Microsoft Skype for Business 2016 Security Technical Implementation, Version: Guide V1R1, Date: 2016-11-14'
		'DISA Microsoft Word 2016 Security Technical Implementation Guide, Version: V1R1, Date: 2016-11-14'
	)
	Sections = @(
		[ReportSection] @{
			Title = "Microsoft Excel 2016 DISA Recommendations"
			AuditInfos = Test-AuditGroup "Microsoft Office 2016 Excel-DISA-V1R2#RegistrySettings"
		}
		[ReportSection] @{
			Title = "Microsoft Outlook 2016 DISA Recommendations"
			AuditInfos = Test-AuditGroup "Microsoft Office 2016 Outlook-DISA-V1R2#RegistrySettings"
		}
		[ReportSection] @{
			Title = "Microsoft PowerPoint 2016 DISA Recommendations"
			AuditInfos = Test-AuditGroup "Microsoft Office 2016 PowerPoint-DISA-V1R1#RegistrySettings"
		}
		[ReportSection] @{
			Title = "Microsoft Skype for Business 2016 DISA Recommendations"
			AuditInfos = Test-AuditGroup "Microsoft Office 2016 SkypeForBusiness-DISA-V1R1#RegistrySettings"
		}
		[ReportSection] @{
			Title = "Microsoft Word 2016 DISA Recommendations"
			AuditInfos = Test-AuditGroup "Microsoft Office 2016 Word-DISA-V1R1#RegistrySettings"
		}
	)
}
