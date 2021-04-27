@{
RootModule = 'TAPAuditor.psm1'
ModuleVersion = '1.0'
GUID = '5a22bfb8-9cda-47b4-8b4f-e03e6f0624fe'
Author = 'Benedikt Böhme, Patrick Helbach'
CompanyName = 'TEAL Technology Consulting GmbH'
Copyright = '(c) 2018, FB Pro GmbH, (c) 2021, Teal Technology Consulting GmbH. All rights reserved.'
Description = 'Allows you to tests your system with the included reports.'
PowerShellVersion = '5.0'
RequiredModules = @(
	'TAPHtmlReport'
)
# RequiredAssemblies = @()
# ScriptsToProcess = @()
# TypesToProcess = @()
# FormatsToProcess = @()
# NestedModules = @()
FunctionsToExport = @(
	'Save-TAPHtmlReport'
	'Invoke-TAPReport'
	'Get-TAPReport'
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
		Tags = @('reporting', 'auditing', 'benchmarks', 'fb-pro', 'html', 'teal')
		LicenseUri = 'https://github.com/teal-technology-consulting/Teal-Audit-Proof/blob/master/LICENSE'
		ProjectUri = 'https://github.com/teal-technology-consulting/Teal-Audit-Proof'
		# IconUri = ''
		# ReleaseNotes = ''

	} # End of PSData hashtable

} # End of PrivateData hashtable
# HelpInfoURI = ''
# DefaultCommandPrefix = 'TAP'
}
