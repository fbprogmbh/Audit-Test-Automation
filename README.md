# Teal Health Check

## Overview

The Teal Health Check gives you the ability to get an overview about the compliance
status of several systems. You can easily create HTML-reports and have a transparent overview over
compliance and non-compliance of explicit setttings and configurations in comparison to industry
standards and hardening guides. 

## Modules

The package consists of the following modules:

* THCHtmlReport
* THCAuditor

## Reports

The *THCAuditor* contains the following reports based on the following benchmarks including the version number. 

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


## Installation

### Manual Installation

See the [Installing a PowerShell module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module) guide for more specific instructions.

1. Download the most [recent release](https://github.com/teal-technology-consulting/Audit-Test-Automation/releases/latest)

2. Extract the archive, for example by using the following commands in Powershell or by using your favourite unzipping toolset.

```Powershell
Expand-Archive -Path ".\THC.zip" -DestinationPath "THC"
```
3. Copy the `THCAuditor` and the `THCHtmlReport` modules to any of the paths of `$env:PSModulePath`.

### Installation from PS Gallery

```Powershell
Install-Module -Name THCAuditor
```

## Usage

Optionally, import the `THCAuditor` module:

```Powershell
Import-Module -Name THCAuditor
```

By default the module creates a new report in the `Documents\THCReports` folder. You can create a report for any report named in the [above table](#reports). Just substitute the `ReportName` with the name of the report.
The force parameter creates the folder if it doesn't exist. For using an alternative Path, see [customization](#customization).

```Powershell
Save-THCHtmlReport -ReportName "PAW" -Force
Save-THCHtmlReport -ReportName "Microsoft Windows Server 2019" -Force
```

## Good to know

* Make sure your execution policy is set to at least remoteSigned (the scripts are not digitally signed)

```powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

* The `THCAuditor` has a dependency on `THCHtmlReport`.
* Some reports take more than a few seconds because hundreds of individual settings and controls checked. So please be patient, the result will satisfy your needs 😉
* If you used old versions of THC you may want to clean up your modules. Be sure you have not integrated THC functionality in reporting processes. In order to accomplish this task you can use the following script.


## Sample reports

You can find several sample reports in the "Samples" folder.

## Customization

You can change the default folder for `Save-THCHtmlReport`, which is `Documents\THCReports`, by creating and later editing the environment variable `THCReportPath`. 
Environment variables can bet set for different scopes - please choose the one that fits your needs. The following samples will set the default path to 'C:\THCReports'.

Temporary scope: CurrentSession
```Powershell
$env:THCReportPath = 'C:\THCReports'
```

Permanent scope: CurrentUser
```Powershell
[System.Environment]::SetEnvironmentVariable('THCReportPath','C:\THCReports',[System.EnvironmentVariableTarget]::User)
```
Permanent scope: Machine
```Powershell
[System.Environment]::SetEnvironmentVariable('THCReportPath','C:\THCReports',[System.EnvironmentVariableTarget]::Machine)
```

 ## Related links

* Github-Link: https://github.com/teal-technology-consulting/Audit-Test-Automation
* Our Homepage: https://www.teal-consulting.de/
