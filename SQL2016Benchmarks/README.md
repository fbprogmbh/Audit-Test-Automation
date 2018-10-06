# CIS SQL 2016 Benchmarks

_based on CIS Microsoft SQL Server Benchmark v1.0.0 - 08-11-2017_

## Overview

The `CISSQL2016Benchmarks`-Module benchmarks the current systems settings with current hardening standards such as the CIS Microsoft SQL Server Benchmarks. This module is specifically designed for Microsof SQL Server 2016.

## Requirements

Please make sure that following requirements are fulfilled:

* **Windows Server 2016** comes out of the box with:
    * **PowerShell 5.1**
* **SqlServer Module:** The audit module uses Cmdlets from the SqlServer module which is *not* included with a standard sql server installation.
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](../ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.

## Loading the CIS SQL 2016 Benchmarks module

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\CIS_Benchmarks\CISSQL2016Benchmarks -Verbose
```
3. Set your Server Instance with `Set-SQLServerInstance` For example:
```Powershell
Set-SQLServerInstance MyComputer\MyMSSQLServer
```
4. Generate a report with `Get-SQL2016Report` For example:
```PowerShell
Get-SQL2016Report -Path "MyReport.html"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.
