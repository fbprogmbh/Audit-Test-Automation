@{
RootModule = 'ATAPAuditor.psm1'
ModuleVersion = '5.13.0'
GUID = '1662a599-4e3a-4f72-a844-9582077b589e'
Author = 'Phan Quang Nguyen, Daniel Ströher, Robin Wernz'
CompanyName = 'FB Pro GmbH'
Copyright = '(c) 2025 FB Pro GmbH. All rights reserved.'
Description = 'AuditTAP allows you to check operating systems and applications against industry approved standards for secure configuration and delivers the results in form of a HTML based report document.'
PowerShellVersion = '5.0'
RequiredModules = @(
	'ATAPHtmlReport'
)
# RequiredAssemblies = @()
# ScriptsToProcess = @()
# TypesToProcess = @()
# FormatsToProcess = @()
# NestedModules = @()
FunctionsToExport = @(
	'Save-ATAPHtmlReport'
	'Invoke-ATAPReport'
	'Get-ATAPReport'
	'Get-AuditResource'
	'Test-AuditGroup'
)
CmdletsToExport = @()
VariablesToExport = ''
AliasesToExport = @(
	'shr'
)
# ModuleList = @()
# FileList = @()
PrivateData = @{
	PSData = @{
		Tags = @('reporting', 'auditing', 'benchmarks', 'fb-pro', 'html')
		LicenseUri = 'https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/LICENSE'
		ProjectUri = 'https://github.com/fbprogmbh/Audit-Test-Automation'
		# IconUri = ''
		# ReleaseNotes = ''

	} # End of PSData hashtable

} # End of PrivateData hashtable
# HelpInfoURI = ''
# DefaultCommandPrefix = 'ATAP'
}
