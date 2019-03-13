# Windows 10 Audit

based on
* _Windows 10 Security Technical Implementation Guide V1R16 2019-01-25_

## Overview

The `Windows10Audit`-Module benchmarks the current systems settings with current hardening standards from the DISA Security Technical Implementation Guide. This module is designed for Windows 10.

## Requirements

Please make sure that following requirements are fulfilled:

* **Windows 10**
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](https://github.com/fbprogmbh/Audit-Test-Automation/tree/master/ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.

## Loading the Windows 10 Audit module

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\Audit-Test-Automation\Windows10Audit -Verbose
```
3. Generate a report with `Get-Windows10HtmlReport` For example:
```PowerShell
Get-Windows10HtmlReport -Path "MyReport.html"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.

## Remarks

At the moment, all negative audit status results are written as an error on the command line. If your system hasn't been hardened yet, the script will therefore write a lot of errors.
Script runs a while - do not be impatient and expect the HTML report with pleasant anticipation.
