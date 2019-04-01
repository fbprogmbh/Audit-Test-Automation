# Google Chrome Audit

based on
* _Google Chrome Security Technical Implementation Guide V1R15 2019-01-25._

## Overview

The `GoogleChromeAudit`-Module benchmarks the current Google Chrome browser settings with current hardening standards from DISA Security Technical Implementation Guide. This module is designed for Google Chrome.

## Requirements

Please make sure that following requirements are fulfilled:

* **Google Chrome browser**
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](https://github.com/fbprogmbh/Audit-Test-Automation/tree/master/ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.

## Loading the Google Chrome Audit module

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\Audit-Test-Automation\GoogleChromeAudit -Verbose
```
3. Generate a report with `Get-GoogleChromeHtmlReport` For example:
```PowerShell
Get-GoogleChromeHtmlReport -Path "MyReport.html"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.

## Remarks

None.
