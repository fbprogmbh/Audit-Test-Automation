# ATAP Html Report

## Overview

A module part of the *Audit Test Automation Package* that creates html reports with tables and sections for audit reporting.

## Requirements

Please make sure, that following requirements are fulfilled:

* **PowerShell 5.1:** To find out the current version use `$PSVersionTable.PSVersion`.

## Installation

It is recommended that you install the module on your system. 

1. Findout out where PowerShell stores modules with `$env:PSModulePath`. For example, this folder might be C:\Users\Administrator\Documents\WindowsPowerShell\Modules.
2. Copy this folder into the modules folder
3. Check with `Get-Module ATAPHtmlReport -ListAvailable` if PowerShell detects the module.

## Troubleshooting
The cmdlet `import-module` is not the required installation. Please follow the outlined steps above.
