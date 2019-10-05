# Windows 10 General Data Protection Regulation (GDPR) Audit

based on
* _Windows 10 GDPR settings by Microsoft_
* _Windows 10 GDPR settings by Bundesamt für Sicherheit in der Informationstechnik (BSI)_

## Overview

The `Windows10_GDPRAudit`-Module benchmarks the current systems settings with current GDPR recommendations from Microsoft and BSI. This module is designed for Windows 10.

## Requirements

Please make sure that following requirements are fulfilled:

* **Windows 10**
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](https://github.com/fbprogmbh/Audit-Test-Automation/tree/master/ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.

## Loading the Windows 10 GDPR Audit module

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\Audit-Test-Automation\Windows10_GDPRAudit -Verbose
```
3. Generate a report with `Get-Windows10_GDPRHtmlReport` For example:
```PowerShell
Get-Windows10_GDPRHtmlReport -Path "MyReport.html"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.

## Remarks

None.
