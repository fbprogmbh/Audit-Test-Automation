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
* Both columns "DISA STIG" and "CIS benchmark" are filled - great, report directly shows conformity to both standards
* "Single" references to one specific benchmark
* "Multiple" directly checks several benchmarks and creates a consolidated report for you
* "None" says we still have work to do ;-)

Benchmark | DISA STIG | CIS benchmark
------------ | ------------- | -------------
Google Chrome | Single (Version: V1R15, Date: 2019-01-28) | Single (Version: 2.0.0, Date: 2019-05-17)
Mozilla Firefox | Single (Version: V4R24, Date: 2019-01-25) | Single (Version: 1.0.0, Date: 2015-12-31)
Microsoft IE11 | Single (Version: V1R16, Date: 2018-06-08 | Single (Version: 1.0.0, Date: 2014-12-01)
Microsoft IIS10 | None | Single (Version: 1.1.0, Date: 2018-11-12)
Microsoft Office 2016 | Multiple (see below) | None
Microsoft Office 2016 Excel | Single (Version: V1R2, Date: 2017-09-19) | None
Microsoft Office 2016 Outlook | Single (Version: V1R2, Date: 2017-05-08) | None
Microsoft Office 2016 PowerPoint | Single (Version: V1R1, Date: 2016-11-02) | None
Microsoft Office 2016 SkypeForBusiness | Single (Version: V1R1, Date: 2016-11-02) | None
Microsoft Office 2016 Word | Single (Version: V1R1, Date: 2016-11-02) | None
Microsoft SQL Server 2016 | None | Single (Version: 1.0.0, Date: 2017-11-08)
Microsoft Windows 10 | Single (Version: V1R16, Date: 2019-10-25) | Single (Version: 1.8.1, Date: 2020-01-28)
Microsoft Windows 10 GDPR | None | None
Microsoft Windows Server 2016 | Single (Version: V1R6, Date: 2018-10-26) | Single (Version: 1.1.0, Date: 2018-10-15)
Microsoft Windows Server 2019 | Single (Version: V1R2, Date: 2020-01-24) | Single (Version: 1.1.0, Date: 2020-01-10)


## Download, installation and usage

### Install from Github (manual way)

1. Download the most recent release here: https://github.com/fbprogmbh/Audit-Test-Automation/releases

2. Unzip  the release package on your local machines, for example by using the following commands in Powershell or by using your favourite unzipping toolset.
```Powershell
Expand-Archive -Path ".\Audit TAP.zip" -DestinationPath "Audit TAP"
```

3. Import the modules "ATAPAuditor" and "ATAPHtmlReport" to any of the paths of `$env:PSModulePath` by using the following code:
```Powershell
Import-Module -Name .\ATAPAuditor\ATAPAuditor.psm1 -Verbose
Import-Module -Name .\ATAPHtmlReport\ATAPHtmlReport.psm1 -verbose
```

4. Create a new report in the `Documents\ATAPReports` folder. You can create a report for any report named in the above table.
The force parameter creates the folder if it doesn't exist. For using an alternative Path, see customization.

```Powershell
Save-ATAPHtmlReport -ReportName "Microsoft IIS10" -Force
Save-ATAPHtmlReport -ReportName "Mozilla Firefox" -Force
```

### Install from PS Gallery

1. You need to install both modules:
```Powershell
Install-Module -Name ATAPAuditor
Install-Module -Name ATAPHtmlReport
```
2. Create a new report in the `Documents\ATAPReports` folder. The force parameter creates the folder if it doesn't exist. For using an alternative Path, see customization.

```Powershell
Save-ATAPHtmlReport -ReportName "Microsoft IIS10" -Force
```
## Good to know

* Make sure your execution policy is set to at least remoteSigned (the scripts are not digitally signed)

```powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

* The `ATAPAuditor` has a dependency on `ATAPHtmlReport`.

* Some reports are running longer than a few seconds due to hundreds of individual settings and controls checked. So please be patient, the result will satisfy your needs ;-)
 
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
