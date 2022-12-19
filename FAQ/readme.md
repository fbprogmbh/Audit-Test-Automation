# Frequently Asked Questions
This section is dedicated to an ever-growing list of frequently asked questions

### Table of contents

1. [Can I keep formatting when printing AuditTAP HTML report as PDF? ](https://github.com/fbprogmbh/Audit-Test-Automation/edit/master/FAQ/readme.md#when-printing-html-to-pdf-color-scheme-formatting-is-lost)

2. [Can we add specific exclusions to be more compliant?](https://github.com/fbprogmbh/Audit-Test-Automation/edit/master/FAQ/readme.md#Can-we-add-specific-exclusions-to-be-more-compliant)

#### When printing html to PDF, color-scheme-formatting is lost

It's not a bug, it's a feature of modern browsers to save ink. As per default, the option to print backgrounds is disabled.
To enable this, expand the section "more settings" and enable "Print backgrounds" (Firefox) / "Background graphics" (Google Chrome).

The following screenshot shows this for Firefox browser.  
![image](https://github.com/fbprogmbh/Audit-Test-Automation/blob/master/FAQ/images/FAQ_print%20backgrounds.PNG)


#### Can we add specific exclusions to be more compliant? 

The scenario often described is as follows: Customer uses another antimalware tool than Microsoft Defender. So all Defender related rules will be non compliant as Microsoft Defender is not in "active mode". This leads to higher "non compliance value". 
At this point of time it is not possible to add ecxlusions or rationals. AuditTAP was designed to be easy to handle and create fast, transparent reports. We are thinking about enhancing the product in this direction - but this is not a short term feature change.
