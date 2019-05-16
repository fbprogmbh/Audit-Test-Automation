# Windows Server 2016 Audit

based on
* _Windows Server 2016 Security Technical Implementation Guide V1R6 2018-08-26_
* and _CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 2018-10-31_

## Overview

The `WindowsServer2016Audit`-Module benchmarks your Windows Server 2016 settings with current hardening standards such as the DISA Security Technical Implementation Guide and the CIS Benchmarks.

## Requirements

Please make sure that following requirements are fulfilled:

* **Windows Server 2016**
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](https://github.com/fbprogmbh/Audit-Test-Automation/tree/master/ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.

## Loading the Windows Server 2016 Audit module

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\Audit-Test-Automation\WindowsServer2016Audit -Verbose
```
3. Generate a report with `Get-WindowsServer2016HtmlReport` For example:
```PowerShell
Get-WindowsServer2016HtmlReport -Path "MyReport.html"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.

## Remarks

The script runs a while - do not be impatient.
