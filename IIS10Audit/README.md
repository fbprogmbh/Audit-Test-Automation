# IIS 10 Audit

## Overview

The `IIS10Audit`-Module benchmarks the current systems settings with current hardening standards such as the CIS Microsoft IIS Benchmarks. This module is specifically designed for Windows Server 2016 with IIS 10.

## Getting started

### Requirements

* Windows Server 2016 which comes with:
    * IIS 10
    * PowerShell 5.1

### Quick Start

1. Download the release zip and export the modules in a location you can easily access with PowerShell
2. Navigate to the location with PowerShell and import the modules with `Import-Module`. For example:
```Powershell
cd .\Desktop\
Import-Module -Name .\Audit-Test-Automation\IIS10Audit -Verbose
```
3. Generate a report with `Get-IISHtmlReport` For example:
```PowerShell
Get-IISHtmlReport -Path "MyReport.html"
```