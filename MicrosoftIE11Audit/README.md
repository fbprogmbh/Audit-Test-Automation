# Internet Explorer 11 Audit

based on
* _Internet Explorer 11 Security Technical Implementation Guide  V1R16 2018-07-27_

## Overview

The `IE11Audit`-Module benchmarks the current systems settings with current hardening standards of the DISA Security Technical Implementation Guide.

## Requirements

Please make sure that following requirements are fulfilled:

* **Internet Explorer 11**
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](https://github.com/fbprogmbh/Audit-Test-Automation/tree/master/ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.

## Loading the IE11Audit module

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\Audit-Test-Automation\IE11Audit -Verbose
```
3. Generate a report with `Get-MsIE11HtmlReport` For example:
```PowerShell
Get-MsIE11HtmlReport -Path "reports/report.html"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.

## Remarks

Rule DTBI1125-IE11 and DTBI1130-IE11 only exist on Windows 10 Redstone 2 or later and will therefore fail on other systems.