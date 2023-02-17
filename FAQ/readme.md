# Frequently Asked Questions
This section is dedicated to an ever-growing list of frequently asked questions

### Table of contents

1. [Can I keep formatting when printing AuditTAP HTML report as PDF? ](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#when-printing-html-to-pdf-color-scheme-formatting-is-lost)

2. [Can we add specific exclusions to be more compliant?](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#Can-we-add-specific-exclusions-to-be-more-compliant)

3. [PowerShell console states commandlet "Save-ATAPHtmlReport" was not found in the module "ATAPAuditor". What to do now?](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#powershell-console-states-commandlet-save-ataphtmlreport-was-not-found-in-the-module-atapauditor-what-to-do-now)


#### When printing html to PDF, color-scheme-formatting is lost [[Back to TOC]](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#table-of-contents)

It's not a bug, it's a feature of modern browsers to save ink. As per default, the option to print backgrounds is disabled.
To enable this, expand the section "more settings" and enable "Print backgrounds" (Firefox) / "Background graphics" (Google Chrome).

The following screenshot shows this for Firefox browser.  
![image](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/images/FAQ_print%20backgrounds.PNG)


#### Can we add specific exclusions to be more compliant? [[Back to TOC]](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#table-of-contents)

The scenario often described is as follows: Customer uses another antimalware tool than Microsoft Defender. So all Defender related rules will be non compliant as Microsoft Defender is not in "active mode". This leads to higher "non compliance value". 
At this point of time it is not possible to add ecxlusions or rationals. AuditTAP was designed to be easy to handle and create fast, transparent reports. We are thinking about enhancing the product in this direction - but this is not a short term feature change.

#### Why is PowerShell console stating commandlet "Save-ATAPHtmlReport" was not found in the module "ATAPAuditor"? [[Back to TOC]](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/readme.md#table-of-contents)

This  happens in case PowerShell "Constrained Language Mode" is activated and execution policy is set to "AllSigned". A simple change of execution policy will help here. We recommend to change it only for the single PowerShell session and not permanent for system or user. The following PowerShell will do the trick:

```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

The following Screenshot shows error and solution: 
![image](https://user-images.githubusercontent.com/23223285/216938169-b92200d4-645b-442c-8d00-de46328e75a0.png)

