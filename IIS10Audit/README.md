# CIS IIS 10 Audit

_based on CIS Microsoft IIS 10 Benchmark v1.1.0 - 12-11-2018"_

## Overview

The `IIS10Audit`-Module benchmarks the current systems settings with current hardening standards such as the CIS Microsoft IIS Benchmarks. This module is specifically designed for Windows Server 2016 with IIS 10.

## Requirements

Please make sure that following requirements are fulfilled:

* **Windows Server 2016** comes out of the box with:
    * **IIS 10**
    * **PowerShell 5.1**
* **ATAPHtmlReport Module:** This module is used for the html report generation and is [included](../ATAPHtmlReport) in the Audit Test Automation Package. Follow the instructions at the link to install the module.


## Installation

The easiest way to get the module is by installing it with `Install-Module -Name IIS10Audit`. This also installs all the dependencies of this module.

### Loading the IIS Audit module

You only need to import the module when you haven't installed it.

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\Audit-Test-Automation\IIS10Audit -Verbose
```
3. Generate a report with `Get-IIS10HtmlReport` For example:
```PowerShell
Get-IIS10HtmlReport -Path "reports/report.html"
```

## Sample report

You can find a sample report in the [Sample](Sample) folder.