# Audit Test Automation Package

ATAPHtmlReport:\
[![atashtmlreportphield](https://img.shields.io/powershellgallery/v/ATAPHtmlReport)](https://www.powershellgallery.com/packages/ATAPHtmlReport)

ATAPAuditor:\
[![atapauditorshield](https://img.shields.io/powershellgallery/v/ATAPAuditor)](https://www.powershellgallery.com/packages/ATAPAuditor)

## Overview

The Audit Test Automation Package gives you the ability to get an overview about the compliance
status of several systems. You can easily create HTML-reports and have a transparent overview over
compliance and non-compliance of explicit setttings and configurations in comparison to industry
standards and hardening guides. 

## Modules

The package consists of the following modules:

* ATAPHtmlReport
* ATAPAuditor

## Reports

The *ATAPAuditor* contains the following reports based on the following benchmarks including the version number. 
How to read the table below:

* The entries in the **DISA** column specify the version of the DISA STIG that is used.
* The entries in the **CIS** column specify the version of the CIS benchmark that is used.
* The entries in the **MS** column specify the version of the Microsoft security baseline that is used.

Report | DISA | CIS | MS | BSI
--------- | -----| --- | -- | ---
Google Chrome | V1R15 | 2.0.0 | - | -
Mozilla Firefox | V4R24 | 1.0.0 | - | -
Microsoft Edge | - | - | 85 | -
Microsoft IE11 | V1R16 | 1.0.0 | - | -
Microsoft IIS10 | - | 1.1.0 | - | -
Microsoft Office 2016 Excel | V1R2 | - | - | -
Microsoft Office 2016 Outlook | V1R2 | - | - | -
Microsoft Office 2016 PowerPoint | V1R1 | - | - | -
Microsoft Office 2016 SkypeForBusiness | V1R1 | - | - | -
Microsoft Office 2016 Word | V1R1 | - | - | -
Microsoft SQL Server 2016 | - | 1.0.0 | - | -
Microsoft Windows 7 | - | 3.1.0 | - | -
Microsoft Windows 10 | V1R16 | 1.8.1 | - | -
Microsoft Windows 10 GDPR | - | - | - | 16082019
Microsoft Windows Server 2016 | V1R6 | 1.1.0 | - | -
Microsoft Windows Server 2019 | V1R2 | 1.1.0 | - | -

The report *Microsoft Office 2016* aggregates the results of all *Microsoft Office 2016 \<Product>* reports.


## Installation

### Manual Installation

See the [Installing a PowerShell module](https://docs.microsoft.com/en-us/powershell/scripting/developer/module/installing-a-powershell-module) guide for more specific instructions.

1. Download the most [recent release](https://github.com/fbprogmbh/Audit-Test-Automation/releases/latest)

2. Extract the archive, for example by using the following commands in Powershell or by using your favourite unzipping toolset.

```Powershell
Expand-Archive -Path ".\Audit TAP.zip" -DestinationPath "Audit TAP"
```
3. Copy the `ATAPAuditor` and the `ATAPHtmlReport` modules to any of the paths of `$env:PSModulePath`.

### Installation from PS Gallery

```Powershell
Install-Module -Name ATAPAuditor
```

## Usage

Optionally, import the `ATAPAuditor` module:

```Powershell
Import-Module -Name ATAPAuditor
```

By default the module creates a new report in the `Documents\ATAPReports` folder. You can create a report for any report named in the [above table](#reports). Just substitute the `ReportName` with the name of the benchmark.
The force parameter creates the folder if it doesn't exist. For using an alternative Path, see [customization](#customization).

```Powershell
Save-ATAPHtmlReport -ReportName "Microsoft IIS10" -Force
Save-ATAPHtmlReport -ReportName "Mozilla Firefox" -Force
```

## Good to know

* Make sure your execution policy is set to at least remoteSigned (the scripts are not digitally signed)

```powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

* The `ATAPAuditor` has a dependency on `ATAPHtmlReport`.
* Some reports take more than a few seconds because hundreds of individual settings and controls checked. So please be patient, the result will satisfy your needs 😉
* If you used old versions of Audit TAP you may want to clean up your modules. Be sure you have not integrated Audit TAP functionality in reporting processes. In order to accomplish this task you can use the following script.

```Powershell
# Remove all old Audit TAP Reports if available
$collection = @("ATAPHtmlReport","Excel2016Audit","GoogleChromeAudit","IIS8Audit","IIS10Audit","MicrosoftIE11Audit","MozillaFirefoxAudit","Outlook2016Audit","Powerpoint2016Audit","Skype4Business2016Audit","SQL2016Benchmarks","Windows10Audit","Windows10GDPRAudit","WindowsServer2016Audit","Word2016Audit")
ForEach ($item in $collection)
{
  if (Get-Module -ListAvailable -Name $item)
  {
    # Module found, so remove it
    $installPath = Get-Module -ListAvailable $item | Select-Object -ExpandProperty Path | Split-Path -Parent
    Remove-Item -Path $installPath -Recurse -Force -Confirm:$false
  }
  else
  {
    # Module not installed, so do nothing an take next item
  }
}
```

## Sample reports

You can find several sample reports in the "Samples" folder.

## Customization

You can change the default folder for `Save-ATAPHtmlReport`, which is `Documents\ATAPReports`, by creating and later editing the environment variable `ATAPReportPath`. 
Environment variables can bet set for different scopes - please choose the one that fits your needs. The following samples will set the default path to 'C:\ATAPReports'.

Temporary scope: CurrentSession
```Powershell
$env:ATAPReportPath = 'C:\ATAPReports'
```

Permanent scope: CurrentUser
```Powershell
[System.Environment]::SetEnvironmentVariable('ATAPReportPath','C:\ATAPReports',[System.EnvironmentVariableTarget]::User)
```
Permanent scope: Machine
```Powershell
[System.Environment]::SetEnvironmentVariable('ATAPReportPath','C:\ATAPReports',[System.EnvironmentVariableTarget]::Machine)
```

 ## Related links

* Github-Link: https://github.com/fbprogmbh/Audit-Test-Automation
* Our Homepage: https://fb-pro.com/

 ## Questions, issues or project support

*  For questions or issues regarding Audit TAP please use Github issue tracker.
*  For questions regarding project support please write a short mail to team@fb-pro.com 
