## Audit Test Automation Package
<div align="center">
	<table>
		<tr>
	<th>Powershell Gallery</th>
	<th>Direct download</th>
		</tr>
		<tr>
			<td>


ATAPAuditor:\
[![atapauditorshield](https://img.shields.io/powershellgallery/v/ATAPAuditor)](https://www.powershellgallery.com/packages/ATAPAuditor)

ATAPHtmlReport:\
[![ataphtmlreportshield](https://img.shields.io/powershellgallery/v/ATAPHtmlReport)](https://www.powershellgallery.com/packages/ATAPHtmlReport)
			</td>
			<td>

[![ATAP](https://www.fb-pro.com/wp-content/uploads/2022/09/atap-download-button.png)](https://github.com/fbprogmbh/Audit-Test-Automation/releases/tag/v5.10.0)
			</td>
		</tr>
	</table>
</div>



## Table of contents

- [Audit Test Automation Package](#audit-test-automation-package)
- [Table of contents](#table-of-contents)
- [Overview](#overview)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
    - [Windows](#windows)
    - [Linux](#linux)
  - [Installation from PS Gallery](#installation-from-ps-gallery)
  - [Video tutorial for manual installation](#video-tutorial-for-manual-installation)
  - [Installer](#installer)
- [Usage](#usage)
- [How to Update](#how-to-update)
- [Reports](#reports)
  - [**Microsoft OS**](#microsoft-os)
  - [**Unix OS**](#unix-os)
  - [**Application**](#application)
- [Questions, issues or project support](#questions-issues-or-project-support)
- [Related links](#related-links)
  - [AuditTAP information](#audittap-information)
  - [Hardening recommendations in general](#hardening-recommendations-in-general)


## Overview

Our Audit Test Automation Package enables you to get an overview about the compliance
status of your systems against established hardening guidelines. Below you will find an overview of the integrated hardening standards and their respective authors (such as Microsoft, CIS, BSI, etc.).
The resulting HTML-reports provide a transparent and comprehensible overview over the compliance-status for each of the different settings and configurations suggested inside the provided industry standards and hardening guides. 

The package consists of the following PowerShell modules:

* ATAPHtmlReport
* ATAPAuditor

## Installation

We offer several ways of how you can use our free of charge . 
Find several detailed explanations below and use them as follows:

* Installation via PSGallery - just install our package directly from PowerShell Gallery.
* Manual installation - use the manual way in case you do not have internet connectivity on the system you want to check. We are aware of these "non connected" scenarios for example in datacenter environments.
* Use our installer to install or update

### Prerequisites

Before proceeding with the installation, please ensure the following prerequisites are met:

#### Windows

* PowerShell version 5.1
* Administrative permissions on the system to be audited

#### Linux
For usage on Linux systems a PowerShell installation is required. The necessary steps depend on the Linux distribution and is documented [here](https://docs.microsoft.com/en-us/PowerShell/scripting/install/installing-PowerShell-on-linux).

### Installation from PS Gallery
Simple and straight-forward. Install  with a single line of code.
```PowerShell
Install-Module -Name ATAPAuditor
```

### Video tutorial for manual installation
Following the well-known phrase "A picture is worth a thousand words" we visualized -installation in a roughly three minute video.
The first half of the video guides through the process of manual installation, the second half shows installation via PowerShell Gallery.

<div align="center">
   <a href="https://www.youtube-nocookie.com/embed/5fJGdHCxqpM">
     <img src="https://img.youtube.com/vi/5fJGdHCxqpM/0.jpg" 
      alt="How to get a transparent system hardening report?" 
     >
   </a>
</div>

See the [Installing a PowerShell module](https://docs.microsoft.com/en-us/PowerShell/scripting/developer/module/installing-a-PowerShell-module) guide for more specific instructions.

1. Download the most [recent release](https://github.com/fbprogmbh/Audit-Test-Automation/releases/latest)
2. In case your systems security configuration prevents direct execution / access on internet based ("untrusted") files you may need to "unblock" the file first. 

```PowerShell
Unblock-File -Path .\Audit-Test-Automation-5.10.0.zip -Verbose
```
The following screenshot shows the output:

![grafik](https://user-images.githubusercontent.com/35689334/208451043-e183cb31-629c-493c-a46b-97d14c002e70.png)

3. Extract the archive, for example by using the following commands in PowerShell or by using your favourite unzipping toolset.  
When using PowerShell, please check correct version number with below code example.

```PowerShell
Expand-Archive -Path ".\Audit-Test-Automation-5.10.0.zip" -DestinationPath "AuditTAP"
```
4. Copy `ATAPAuditor` and `ATAPHtmlReport` modules to any of the paths of `$env:PSModulePath`.


### Installer

Download the installer from the [releases](https://github.com/fbprogmbh/Audit-Test-Automation/releases) page. The wizard will guide you through the installation steps to install the necessary modules, along with a convenient Start-menu shortcut.


## Usage

Optionally, import `ATAPAuditor` module:

```PowerShell
Import-Module -Name ATAPAuditor
```

By default the module creates a new report in `Documents\ATAPReports` folder. A list of all available reports can be found in [above table](#reports). Just substitute the `ReportName` with the name of the benchmark. Append `-Path` to specify output folder.

:exclamation: 
ATAP is only compatible with PowerShell 5.1. When run in a different PowerShell version, the user will be prompted to open a PowerShell 5 console or stop the script.
:exclamation: 

**Examples:**
```PowerShell
Save-ATAPHtmlReport -ReportName "Microsoft Windows 11 Stand-alone" -RiskScore -Path C:\Temp\report.html
Save-ATAPHtmlReport -ReportName "Microsoft Windows 10" -RiskScore -Path C:\Temp\report.html
Save-ATAPHtmlReport -ReportName "Microsoft Windows 11" -Path C:\Temp\report.html
Save-ATAPHtmlReport -ReportName "Microsoft Windows 10 BSI" -RiskScore -Path C:\Temp
Save-ATAPHtmlReport -ReportName "Microsoft Windows Server 2022" -Path C:\Temp
Save-ATAPHtmlReport -ReportName "Google Chrome"
Save-ATAPHtmlReport -ReportName "Ubuntu 20.04"
```
Pro-Tip: After typing *Save-ATAPHtmlReport -ReportName*, use the keyboard shortcut `<ctrl>` + `<space>` to display all available parameters and select the desired  report using arrow-keys.

The `ATAPAuditor` module also provides a simple menu based runner for reports. It can be found in `ATAPAuditor\Helpers\Menu.ps1`. When using the Windows based installer, a shortcut can be found in the start menu.

## How to Update
If you already have AuditTAP installed and want to update it, you can find detailed instructions in our [Wiki](https://github.com/fbprogmbh/Audit-Test-Automation/wiki), along with other useful and interesting information.

## Reports

*ATAPAuditor* contains reports based on the following benchmarks including the version number. 
How to read the table below:

* The entries in the **DISA** column specify the version of the DISA STIG that is used.
* The entries in the **CIS** column specify the version of the CIS benchmark that is used.
* The entries in the **MS** column specify the version of the Microsoft security baseline that is used.
* The entries in the **BSI** column specify the version of the BSI benchmark that is used.
* The entries in the **ACSC** column specify the version of the ACSC benchmark that is used.

We currently support the following reports, based on these topics:

### **Microsoft OS**

Report | DISA | CIS | Microsoft | BSI | ACSC
--------- | -----| --- | -- | --- | ---
Microsoft Windows 7 | - | 3.1.0 | - | - | -
Microsoft Windows 10 | V1R23 | 2.0.0 | 21H1 | SiSyPHuS 1.3 | 21H1
Microsoft Windows 10 GDPR | - | - | 16082019 | V1.1 | -
Microsoft Windows 10 BSI | - | - | - | SiSyPHuS 1.3 | -
Microsoft Windows 10 Stand-alone | - | Stand-alone 2.0.0 | - | SiSyPHuS 1.3 (Stand-alone) | -
Microsoft Windows 11 Stand-alone | - | Stand-alone 2.0.0 | - | SiSyPHuS 1.3 (Stand-alone) | -
Microsoft Windows 11 | - | 3.0.0 | 22H2 | SiSyPHuS 1.3 | -
Microsoft Windows Server 2012 | 2.19 | 2.6.0 | - | - | -
Microsoft Windows Server 2016 | 1.12 | 2.0.0 | FINAL | - | -
Microsoft Windows Server 2019 | 1.5 | 2.0.0 | FINAL | - | -
Microsoft Windows Server 2022 | V1R1 | 2.0.0 | FINAL | - | -

The report *Microsoft Windows 10 BSI* aggregates the results of all *BSI recommendations for Microsoft Windows 10* reports.

### **Unix OS**

Report | DISA | CIS | Microsoft | BSI | ACSC | FB Pro
--------- | -----| --- | -- | --- | --- | ---
Debian 10 | - | - | - | - | - | Base
Debian 11 | - | 1.0.0 | - | - | - | -
Fedora 35 | - | - | - | - | - | Base
Red Hat Enterprise Linux 9 | - | 1.0.0 | - | - | - | -
SUSE Linux Enterprise 15 | - | 1.1.1 | - | - | - | -
Ubuntu 20.04 | - | 1.1.0 | - | - | - | -
Ubuntu 22.04 | - | 1.0.0 | - | - | - | -

### **Application**

Report | DISA | CIS | Microsoft | BSI | ACSC
--------- | -----| --- | -- | --- | ---
Google Chrome | V1R15 | 2.0.0 | - | - | -
Mozilla Firefox | V4R24 | 1.0.0 | - | - | -
Microsoft Edge | - | 2.0.0 | 117 | - | -
Microsoft Internet Explorer 11 | V1R16 | 1.0.0 | 2004 | - | -
Microsoft IIS10 | - | 1.1.1 | - | - | -
Microsoft Office 2016 Excel | V1R2 | - | - | - | -
Microsoft Office 2016 Outlook | V1R2 | - | - | - | -
Microsoft Office 2016 PowerPoint | V1R1 | - | - | - | -
Microsoft Office 2016 SkypeForBusiness | V1R1 | - | - | - | -
Microsoft Office 2016 Word | V1R1 | - | - | - | -
Microsoft Office 2016 | V1R1, V1R2 | 1.1.0 | - | - | -
Microsoft SQL Server 2016 | - | 1.3.0 | - | - | -

The report *Microsoft Office 2016* aggregates the results of all *Microsoft Office 2016 \<Product>* reports.  


## Questions, issues or project support
Please check the [FAQ-section](https://github.com/fbprogmbh/Audit-Test-Automation/tree/master/FAQ) first before opening an issue or contacting us.

*  For questions or issues regarding AuditTAP please use GitHub issue tracker.
*  For questions regarding project support please write a short mail to team@fb-pro.com 

## Related links

### AuditTAP information

* GitHub-Link: https://github.com/fbprogmbh/Audit-Test-Automation
* AuditTAP landing page: https://www.fb-pro.com/audit-tap-product-information
* YouTube channel with more videos: https://www.youtube.com/channel/UCFolaYgClJ005glpn5owRUg
* For the installer we are using the free Inno Setup for Windows provided by Jordan Russell and Martijn Laan. https://jrsoftware.org/isinfo.php

### Hardening recommendations in general
* #NoCodeHardening: https://www.nocodehardening.com
* BSI SiSyPHus: [https://www.bsi.bund.de/EN/Topics/Cyber-Security/Recommendations/SiSyPHuS_Win10/SiSyPHuS_node.html](https://www.bsi.bund.de/EN/Service-Navi/Publikationen/Studien/SiSyPHuS_Win10/SiSyPHuS.html)
* Center for Internet Security: https://www.cisecurity.org/
* DISA STIGs: https://public.cyber.mil/stigs/
* Microsoft Security baselines: https://techcommunity.microsoft.com/t5/microsoft-security-baselines/bg-p/Microsoft-Security-Baselines






