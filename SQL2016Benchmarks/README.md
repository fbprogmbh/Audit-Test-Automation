# SQL 2016 Benchmarks

_based on CIS Microsoft SQL Server Benchmark v1.0.0 - 08-11-2017_

## Overview

The `SQL2016Benchmarks`-Module benchmarks the current systems settings with current hardening standards such as the CIS Microsoft SQL Server Benchmarks. This module is specifically designed for Microsof SQL Server 2016.

## Requirements

Please make sure that following requirements are fulfilled:

* **Windows Server 2016** comes out of the box with:
    * **PowerShell 5.1**
* **SqlServer Module:** The audit module uses Cmdlets from the SqlServer module which is *not* included with a standard sql server installation.
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](../ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.

## Loading the SQL 2016 Benchmarks module

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\CIS_Benchmarks\CISSQL2016Benchmarks -Verbose
```
3. You can generate a report with `Get-SQL2016Report` for either all SQLInstances without using the Parameter `-SQLInstance` or a specific SQLInstance by using the Parameter `-SQLInstance`. For example:
```PowerShell
Get-SQL2016Report -Path "MyReport.html"
```
```PowerShell
Get-SQL2016Report -Path "MyReport.html" -SQLInstance "MyNamedInstance"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.
