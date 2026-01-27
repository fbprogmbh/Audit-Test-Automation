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

[![ATAP](https://www.fb-pro.com/wp-content/uploads/2022/09/atap-download-button.png)](https://github.com/fbprogmbh/Audit-Test-Automation/releases/tag/v5.12.1)
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
  - [Video Tutorials](#video-tutorials)
  - [Installation Methods](#installation-methods)
    - [PowerShell Gallery](#ps-gallery)
    - [Manual Installation](#manual-installation)
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

The Audit Test Automation Package (AuditTAP or ATAP) provides a holistic overview of the compliance of your systems based on industry-established, state-of-the-art hardening guidelines created by leading institutions (e.g., CIS, Microsoft, BSI), enabling a reliable and concrete assessment of compliance with security standards.

Generated HTML reports provide a transparent and detailed summary of the compliance status for each relevant setting and configuration specified in the selected hardening guideline.

AuditTAP consists of the following PowerShell modules:

* **ATAPHtmlReport** – generates comprehensive HTML compliance reports.
* **ATAPAuditor** – audits configurations against established hardening guidelines.

## Installation

There are several ways to install and use ATAP. Choose the method that best fits your environment.

### Prerequisites

Select the method that best suits your environment.

#### Windows

* PowerShell version 5.1 is required on the system. Please check your current PowerShell version by running the following command:
```PowerShell
$PSVersionTable.PSVersion
```
* Administrative permissions are required on the system to be audited for querying necessary system data. Please note that the tool only generates a report. No changes are made to the system.

#### Linux
A PowerShell installation is required for usage on Linux systems. The installation steps vary by Linux distribution and are documented <a href="https://docs.microsoft.com/en-us/PowerShell/scripting/install/installing-PowerShell-on-linux" target="_blank" rel="noopener noreferrer">here</a>.

### Video tutorials
Below you will find short tutorials for Windows and Linux systems. These videos explain various installation methods for AuditTAP, how to create an AuditTAP report, and how an AuditTAP HTML report is structured.

| Windows Installation | Linux Installation |
|----------------------|--------------------|
| [![Windows Video](https://img.youtube.com/vi/CY3dm1_Wlgc/0.jpg)](https://youtu.be/CY3dm1_Wlgc) | [![Linux Video](https://img.youtube.com/vi/xhADhdKXgfc/0.jpg)](https://www.youtube.com/watch?v=xhADhdKXgfc) |


### Installation Methods
The following installation options are available for Windows. Detailed instructions can also be found below. 
- **PS Gallery**
- **Manual Installation**
- **Installer**

#### PS Gallery
Installing from the PowerShell Gallery is simple and straightforward. Run the following command:
```PowerShell
Install-Module -Name ATAPAuditor
```
Note: Ensure you are running PowerShell with administrative privileges to install the module successfully.


See the [Installing a PowerShell module](https://docs.microsoft.com/en-us/PowerShell/scripting/developer/module/installing-a-PowerShell-module) guide for more specific instructions.

#### Manual Installation
1. Download the most [recent release](https://github.com/fbprogmbh/Audit-Test-Automation/releases/latest)
2. If your system's security configuration prevents direct execution or access to internet based ("untrusted") files, you may need to "unblock" the file first to allow execution. 

```PowerShell
Unblock-File -Path .\Audit-Test-Automation-5.12.1.zip -Verbose
```
The following screenshot shows the expected output:

![grafik](https://user-images.githubusercontent.com/35689334/208451043-e183cb31-629c-493c-a46b-97d14c002e70.png)

3. Extract the archive using PowerShell (adjust the version number as needed) or your preferred unzipping toolset.

```PowerShell
Expand-Archive -Path ".\Audit-Test-Automation-5.12.1.zip" -DestinationPath "AuditTAP"
```
4. Copy the `ATAPAuditor` and `ATAPHtmlReport` modules into one of the directories listed in `$env:PSModulePath` to make them accessible in PowerShell. Use the `$env:PSModulePath` command to view available directories.


#### Installer

Download the installer from the [releases](https://github.com/fbprogmbh/Audit-Test-Automation/releases) page. The installation wizard will guide you through the steps, including installing the necessary modules and creating a convenient Start menu shortcut.


## Usage

Optionally, you can import `ATAPAuditor` module:

```PowerShell
Import-Module -Name ATAPAuditor
```

By default the module creates a new report in `Documents\ATAPReports` folder. If you wish to specify a different output folder, you can use the `-Path` parameter.

A list of all available reports can be found in this [table](#reports) further down in this document. Just substitute `ReportName` with the name of the benchmark.


:exclamation: 
**ATAP is only compatible with PowerShell 5.1.** If you run it in a different PowerShell version, you will be prompted to open a PowerShell 5 console or stop the script.
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
Pro-Tip: After typing *Save-ATAPHtmlReport -ReportName*, use the keyboard shortcut `<ctrl>` + `<space>` to display all available parameters. You can then select the desired report using the arrow keys. This feature is available once the module is imported.

The `ATAPAuditor` module also provides a simple menu-based runner for reports. It can be found in `ATAPAuditor\Helpers\Menu.ps1`. When using the Windows based installer, a shortcut can be found in the start menu.

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
Microsoft Windows 11 | - | 4.0.0 | 22H2 | SiSyPHuS 1.3 | -
Microsoft Windows Server 2012 (R2) | V2R19 | 3.0.0 | - | - | -
Microsoft Windows Server 2016 | V1R12 | 3.0.0 | FINAL | - | -
Microsoft Windows Server 2019 | V1R5 | 3.0.0 | FINAL | - | -
Microsoft Windows Server 2022 | V1R1 | 3.0.0 | FINAL | - | -
Microsoft Windows Server 2025 | V1R1 | 1.0.0 | FINAL | - | -

The report *Microsoft Windows 10 BSI* aggregates the results of all *BSI recommendations for Microsoft Windows 10* reports.

### **Unix OS**

Report | DISA | CIS | Microsoft | BSI | ACSC | FB Pro
--------- | -----| --- | -- | --- | --- | ---
Debian 10 | - | - | - | - | - | Base
Debian 11 | - | 1.0.0 | - | - | - | -
Debian 12 | - | 1.0.1 | - | - | - | -
Fedora 35 | - | - | - | - | - | Base
Red Hat Enterprise Linux 9 | - | 1.0.0 | - | - | - | -
SUSE Linux Enterprise 15 | - | 1.1.1 | - | - | - | -
Ubuntu 20.04 | - | 1.1.0 | - | - | - | -
Ubuntu 22.04 | - | 2.0.0 | - | - | - | -

### **Application**

Report | DISA | CIS | Microsoft | BSI | ACSC
--------- | -----| --- | -- | --- | ---
Google Chrome | V1R15 | 2.0.0 | - | - | -
Mozilla Firefox | V4R24 | 1.0.0 | - | - | -
Microsoft Edge | - | 4.0.0 | 117 | - | -
Microsoft Internet Explorer 11 | V1R16 | 1.0.0 | 2004 | - | -
Microsoft IIS10 | - | 1.1.1 | - | - | -
Microsoft Office <br><sub>for Office 2016, 2019, 2021 and 365 | - | 1.2.0 | - | - | -
Microsoft SQL Server 2016 | - | 1.3.0 | - | - | -


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
