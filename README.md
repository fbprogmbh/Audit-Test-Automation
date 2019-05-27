# Audit Test Automation Package

## Overview

The Audit Test Automation Package gives you the ability to get an overview about the compliance status of several systems. You can easily create HTML-reports and have a transparent overview over compliance and non-compliance of explicit setttings and configurations in comparison to industry standards and hardening guides.

## Modules

The package consists of the following Modules:

* [ATAPHtmlReport](ATAPHtmlReport)
* [IIS8Audit](IIS8Audit)
* [IIS10Audit](IIS10Audit)
* [SQL2016Benchmarks](SQL2016Benchmarks)
* [WindowsServer2016Audit](WindowsServer2016Audit)
* [Windows10Audit](Windows10Audit)

Microsoft Office 2016 Audit Modules:

* [Word2016Audit](Word2016Audit)
* [Excel2016Audit](Excel2016Audit)
* [Outlook2016Audit](Outlook2016Audit)
* [Powerpoint2016Audit](Powerpoint2016Audit)
* [Skype4Business2016Audit](Skype4Business2016Audit)

Browser Audit Modules:

* [MozillaFirefoxAudit](MozillaFirefoxAudit)
* [GoogleChromeAudit](GoogleChromeAudit)
* [MicrosoftIE11Audit](MicrosoftIE11Audit)

Read the the READMEs of each module to get specific information about a module.

## Getting started

Check out the module folders and check if the desired module can be installed with `Install-Module`. Otherwise:

### General Requirements

* Make sure your execution policy is set to at least remoteSigned (the scripts are not digitally signed yet)

```powershell
	Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

### Quick Usage

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. Be sure not to include any file extension, as this prevents the module manifest from loading. This is important because the manifest tells Powershell about the assemblies and modules that the module requires. For example:
```Powershell
Import-Module -Name .\IIS10Audit -Verbose
```
3. Run the command you require.

## More Information

You can always get more information on a command by using the familiar `Get-Help`-Command on a Module.

For example:
```Powershell
Get-Help Get-IIS10HtmlReport
```
Output:
```
NAME
    Get-IISHtmlReport

SYNOPSIS
    Generates an audit report in an html file.


SYNTAX
    Get-IISHtmlReport [-Path] <String> [[-SystemAuditInfos] <AuditInfo[]>] [[-SiteAudits] <SiteAudit[]>]
    [<CommonParameters>]


DESCRIPTION
    The `Get-IIS10HtmlReport` cmdlet collects by default data from the current machine to generate an audit report.

    It is also possible to pass your own data to the cmdlet from which it generates the report. To do this, use the
    parameter `SystemAuditInfos` and `SiteAudits`.


RELATED LINKS

REMARKS
    To see the examples, type: "get-help Get-IIS10HtmlReport -examples".
    For more information, type: "get-help Get-IIS10HtmlReport -detailed".
    For technical information, type: "get-help Get-IIS10HtmlReport -full".

```
