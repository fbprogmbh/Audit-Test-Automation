# Mozilla Firefox Audit

based on
* _CIS Mozilla Firefox 38 ESR Benchmark v1.0.0 - 2015-12-31_
* _DISA Mozilla FireFox Security Technical Implementation Guide V4R24 2019-01-25_

## Overview

The `MozillaFirefoxAudit`-Module benchmarks the current Mozilla Firefox browser preference settings with current hardening standards from CIS and DISA.

## Requirements

Please make sure that following requirements are fulfilled:

* **Mozilla Firefox browser**
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](https://github.com/fbprogmbh/Audit-Test-Automation/tree/master/ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.

## Loading the Mozilla Firefox Audit module

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\Audit-Test-Automation\MozillaFirefoxAudit -Verbose
```
3. Generate a report with `Get-MozillaFirefoxHtmlReport` For example:
```PowerShell
Get-MozillaFirefoxHtmlReport -Path "reports/report.html"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.

## Remarks

None.
