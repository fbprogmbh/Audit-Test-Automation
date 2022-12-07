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
* The entries in the **BSI** column specify the version of the BSI benchmark that is used.
* The entries in the **ACSC** column specify the version of the ACSC benchmark that is used.

Report | DISA | CIS | Microsoft | BSI | ACSC
--------- | -----| --- | -- | --- | ---
Debian 10 | - | - | - | - | -
Fedora 35 | - | - | - | - | -
Google Chrome | V1R15 | 2.0.0 | - | - | -
Mozilla Firefox | V4R24 | 1.0.0 | - | - | -
Microsoft Edge | - | - | 99 | - | -
Microsoft Internet Explorer 11 | V1R16 | 1.0.0 | 2004 | - | -
Microsoft IIS10 | - | 1.1.1 | - | - | -
Microsoft Office 2016 Excel | V1R2 | - | - | - | -
Microsoft Office 2016 Outlook | V1R2 | - | - | - | -
Microsoft Office 2016 PowerPoint | V1R1 | - | - | - | -
Microsoft Office 2016 SkypeForBusiness | V1R1 | - | - | - | -
Microsoft Office 2016 Word | V1R1 | - | - | - | -
Microsoft Office 2016 | V1R1, V1R2 | 1.1.0 | - | - | -
Microsoft SQL Server 2016 | - | 1.3.0 | - | - | -
Microsoft Windows 7 | - | 3.1.0 | - | - | -
Microsoft Windows 10 | V1R16 | 1.12.0 | 21H1 | SiM-08202, SiSyPHuS 1.3 | 10.2021
Microsoft Windows 10 GDPR | - | - | 16082019 | V1.1 | -
Microsoft Windows 10 BSI | - | - | - | SiM-08202, SiSyPHuS 1.3 | -
Microsoft Windows 10 All | V1R16 | 1.12.0 | 21H1 | SiM-08202, SiSyPHuS 1.3 | 10.2021
Microsoft Windows 11 | - | 1.0.0 | 20H2 | SiM-08202, SiSyPHuS 1.3 | -
Microsoft Windows Server 2012 R2 | 2.19 | 2.5.0 | - | - | -
Microsoft Windows Server 2016 | 1.12 | 1.2.0 | FINAL | - | -
Microsoft Windows Server 2016 DC | V1R6 | 1.2.0 | FINAL | - | -
Microsoft Windows Server 2019 | 1.5 | 1.3.0 | FINAL | - | -
Microsoft Windows Server 2019 DC | V1R2 | 1.1.0 | FINAL | - | -
Microsoft Windows Server 2022 | - | 1.0.0 | FINAL | - | -
Red Hat Enterprise Linux 8 | - | - | - | - | -
Ubuntu 20.04 | - | - | - | - | -

The report *Microsoft Office 2016* aggregates the results of all *Microsoft Office 2016 \<Product>* reports.
The report *Microsoft Windows 10 BSI* aggregates the results of all *BSI recommendations for Microsoft Windows 10 1809* reports.

Short explanation for BSI (see related links):
 * Normal protection needs standalone computer (NE)
 * Normal protection needs domain member (ND)
 * Increased protection needs domain member (HD)
 * Logging and forensics for all profiles (Logging)

## Installation
We offer several ways of how you can use our free of charge AuditTAP. 
Find several detailed explanations below and use them as follows:

* Video tutorial - following the well known phrase "A picture is worth a thousand words" we visualized the installation of AuditTAP in a roughly three minute video. Have fun!
* Manual installation - use the manual way in case you do not have internet connectivity on the system you want to check. We are aware of these "non connected" scenarios for example in datacenter environments.
* The most easy automated way - just install our package directly from PowerShell Gallery.

### Video tutorials
Find following tutorials suitable for your needs:

[![How to get a transparent system hardening report?](https://img.youtube.com/vi/5fJGdHCxqpM/0.jpg)](https://www.youtube.com/watch?v=5fJGdHCxqpM)

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

### Installer

Download the installer from the [releases](https://github.com/fbprogmbh/Audit-Test-Automation/releases) page. The wizard will guide you through the installation steps. Additionally to the modules, it also installs a shortcut to the menu based runner in the start menu.

### Linux
For usage on Linux systems a Powershell installation is required. The neccessary steps depend on the type of Linux distribution and is documented [here](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux). Once Powershell is installed proceed with a [manual](#manual-installation) installation or using the [PS Gallery](#installation-from-ps-gallery).

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

The `ATAPAuditor` module also provides a simple menu based runner for reports. It can be found in `ATAPAuditor\Helpers\Menu.ps1`. When using the Windows based installer, a shortcut can be found in the start menu.

## Good to know

* Make sure your execution policy is set to at least remoteSigned (the scripts are not digitally signed)

```powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

* You can extend your AuditReports with a RiskScore by adding the RiskScore-Switch parameter (currently only available for Windows Reports):
```powershell
Save-ATAPHtmlReport -ReportName "Microsoft Windows 10" -Force -RiskScore
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

### Audit TAP information

* Github-Link: https://github.com/fbprogmbh/Audit-Test-Automation
* Audit TAP landing page: https://www.fb-pro.com/audit-tap-product-information
* Youtube channel with more videos: https://www.youtube.com/channel/UCFolaYgClJ005glpn5owRUg

### Hardening recommendation in general
* #NoCodeHardening: https://www.nocodehardening.com
* BSI SiSyPHus: https://www.bsi.bund.de/EN/Topics/Cyber-Security/Recommendations/SiSyPHuS_Win10/SiSyPHuS_node.html
* Center for Internet Security: https://www.cisecurity.org/
* DISA STIGs: https://public.cyber.mil/stigs/
* Microsoft Security baselines: https://techcommunity.microsoft.com/t5/microsoft-security-baselines/bg-p/Microsoft-Security-Baselines

 ## Questions, issues or project support

*  For questions or issues regarding Audit TAP please use Github issue tracker.
*  For questions regarding project support please write a short mail to team@fb-pro.com 

