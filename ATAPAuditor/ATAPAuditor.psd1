@{
RootModule = 'ATAPAuditor.psm1'
ModuleVersion = '5.11.0'
GUID = '1662a599-4e3a-4f72-a844-9582077b589e'
Author = 'Benedikt Böhme, Patrick Helbach, Steffen Winternheimer, Phan Quang Nguyen, Daniel Ströher'
CompanyName = 'FB Pro GmbH'
Copyright = '(c) 2023 FB Pro GmbH. All rights reserved.'
Description = 'Allows you to tests your system with the included reports.'
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
