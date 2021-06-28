# Teal Audit Proof
## Overview

The Teal Audit Proof provides the ability to generate a compliance overview of your system.
You can easily create HTML-reports and have a transparent overview over
compliance and non-compliance of explicit setttings and configurations in comparison to industry
standards and hardening guides. 

## Modules

The package consists of the following modules:

* TAPHtmlReport
* TAPAuditor

## Reports

The *TAPAuditor* contains the following reports based on the following benchmarks including the version number. 

**Reports**
* PAW
* Microsoft Windows 10
* Microsoft Windows Server 2016
* Microsoft Windows Server 2019
* Microsoft Windows Server 2019 DC

Benchmark | PAW | Microsoft Windows 10 | Microsoft Windows Server 2016 | Microsoft Windows Server 2019 | Microsoft Windows Server 2019 DC 
--------- | -----| --- | -- | --- | -- 
CIS Google Chrome - 2.0.0 | X | - | - | - | - 
CIS Mozilla Firefox - 1.0.0 | X | - | - | - | - 
CIS Microsoft Office 2016 - 1.1.0 | - | X | - | - | - 
CIS Microsoft Windows 10 - 1.9.0| X | X | - | - | -
CIS Microsoft Windows Server 2016 - 1.2.0 | - | - | X | - | - 
CIS Microsoft Windows Server 2019 - 1.1.0 | - | - | - | X | X
Microsoft Security Baseline Edge - 85 | X | - | - | - | - 
Microsoft Security Baseline Windows 10 - 20H2 | X | X | - | - | - 
Microsoft Security Baseline Windows Server 2016 - FINAL | - | - | X | - | -
Microsoft Security Baseline Windows Server 2019 - FINAL | - | - | - | X | -
Microsoft Security Baseline Windows Server 2019 DC - FINAL | - | - | - | - | X
BSI SiSyPHuS Windows 10 - Telemetry components - V1.1 | X | X | X | X | X
Microsoft Windows 10 BSI BPOL | X | X | - | - | -


## Installation

### Manual Installation

See the [Installing a PowerShell module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module) guide for more specific instructions.

1. Download the most [recent release](https://github.com/teal-technology-consulting/Teal-Audit-Proof/releases/latest)

2. Extract the archive, for example by using the following commands in Powershell or by using your favourite unzipping toolset.

```Powershell
Expand-Archive -Path ".\TAP.zip" -DestinationPath "TAP"
```
3. Copy the `TAPAuditor` and the `TAPHtmlReport` modules to any of the paths of `$env:PSModulePath`.

### Installation from PS Gallery

```Powershell
Install-Module -Name TAPAuditor
```

## Usage

NOTE: local administrative permissions are required to generate a compliance report.

Optionally, import the `TAPAuditor` module:

```Powershell
Import-Module -Name TAPAuditor
```

By default the module creates a new report in the `Documents\TAPReports` folder. You can create a report for any report named in the [above table](#reports). Just substitute the `ReportName` with the name of the report.
The force parameter creates the folder if it doesn't exist. For using an alternative Path, see [customization](#customization).

```Powershell
Save-TAPHtmlReport -ReportName "PAW" -Force
Save-TAPHtmlReport -ReportName "Microsoft Windows Server 2019" -Force
```

## Good to know

* Make sure your execution policy is set to at least remoteSigned (the scripts are not digitally signed)

```powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

* The `TAPAuditor` has a dependency on `TAPHtmlReport`.
* Some reports take more than a few seconds because hundreds of individual settings and controls checked. So please be patient, the result will satisfy your needs 😉
* If you used old versions of TAP you may want to clean up your modules. Be sure you have not integrated TAP functionality in reporting processes. In order to accomplish this task you can use the following script.


## Customization

You can change the default folder for `Save-TAPHtmlReport`, which is `Documents\TAPReports`, by creating and later editing the environment variable `TAPReportPath`. 
Environment variables can bet set for different scopes - please choose the one that fits your needs. The following samples will set the default path to 'C:\TAPReports'.

Temporary scope: CurrentSession
```Powershell
$env:TAPReportPath = 'C:\TAPReports'
```

Permanent scope: CurrentUser
```Powershell
[System.Environment]::SetEnvironmentVariable('TAPReportPath','C:\TAPReports',[System.EnvironmentVariableTarget]::User)
```
Permanent scope: Machine
```Powershell
[System.Environment]::SetEnvironmentVariable('TAPReportPath','C:\TAPReports',[System.EnvironmentVariableTarget]::Machine)
```

 ## Related links

* Github-Link: https://github.com/teal-technology-consulting/Teal-Audit-Proof/
* Our Homepage: https://www.teal-consulting.de/
