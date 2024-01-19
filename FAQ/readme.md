# Frequently Asked Questions
This section is dedicated to an ever-growing list of frequently asked questions

### Table of contents

  - [When printing html to PDF, color-scheme-formatting is lost](#when-printing-html-to-pdf-color-scheme-formatting-is-lost-back-to-toc)
  - [Can we add specific exclusions to be more compliant?](#can-we-add-specific-exclusions-to-be-more-compliant-back-to-toc)
  - [When downloading my anti virus scanner detects malicious behavior. What does that mean?](#when-downloading-my-anti-virus-scanner-detects-malicious-behavior-what-does-that-mean)
  - [Why is PowerShell console stating commandlet "Save-ATAPHtmlReport" was not found in the module "ATAPAuditor"?](#why-is-powershell-console-stating-commandlet-save-ataphtmlreport-was-not-found-in-the-module-atapauditor-back-to-toc)
  - [How long does it take to create a report from AuditTAP?](#how-long-does-it-take-to-create-a-report-from-audittap)


#### When printing html to PDF, color-scheme-formatting is lost [[Back to TOC]](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#table-of-contents)

It's not a bug, it's a feature of modern browsers to save ink. As per default, the option to print backgrounds is disabled.
To enable this, expand the section "more settings" and enable "Print backgrounds" (Firefox) / "Background graphics" (Google Chrome).

The following screenshot shows this for Firefox browser.  
![image](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/images/FAQ_print%20backgrounds.PNG)


#### Can we add specific exclusions to be more compliant? [[Back to TOC]](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#table-of-contents)

The scenario often described is as follows: Customer uses another antimalware tool than Microsoft Defender. So all Defender related rules will be non compliant as Microsoft Defender is not in "active mode". This leads to higher "non compliance value". 
At this point of time it is not possible to add ecxlusions or rationals. AuditTAP was designed to be easy to handle and create fast, transparent reports. We are thinking about enhancing the product in this direction - but this is not a short term feature change.


#### When downloading my anti virus scanner detects malicious behavior. What does that mean?

For AuditTAP we are using an open source installer called 'Inno Setup' provided by Jordan Russell. This installer can be detected as a malicious file, which is not the case. This is a common problem which happened to other software providers as well. Here is a link to a stackoverflow question about this topic: 
https://stackoverflow.com/questions/68834409/program-installed-with-inno-setup-seen-as-trojan-wacatac-bml   
If you don't trust this installer at all, you can of course install our tool via PowerShell Gallery or by importing both modules via PowerShell.

#### Why is PowerShell console stating commandlet "Save-ATAPHtmlReport" was not found in the module "ATAPAuditor"? [[Back to TOC]](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#table-of-contents)

This  happens in case PowerShell "Constrained Language Mode" is activated and execution policy is set to "AllSigned". A simple change of execution policy will help here. We recommend to change it only for the single PowerShell session and not permanent for system or user. The following PowerShell will do the trick:

```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

The following Screenshot shows error and solution: 
![image](https://user-images.githubusercontent.com/23223285/216938169-b92200d4-645b-442c-8d00-de46328e75a0.png)



#### How long does it take to create a report from AuditTAP?
Depending on the size of the report you want to create, the time it takes to create varies. Here are some measurements:
* ~ 50 seconds (Google Chrome) 
* ~ 2 minutes 30 seconds (Microsoft Windows 10)
Each Audit-Test takes some time and depending on the amount of tests, the final report needs some time to finalise.
