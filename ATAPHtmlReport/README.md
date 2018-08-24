# ATAP Html Report

## Overview

This module is required by the other modules to create reports.

## Requirements

Please make sure, that following requirements are fulfilled:

* **PowerShell 5.1:** To find out the current version use `$PSVersionTable.PSVersion`.

## Installation

It is recommended that you install the module on your system. 

1. Findout out where PowerShell stores modules with `$env:PSModulePath`. For example, this folder might be C:\Users\Administrator\Documents\WindowsPowerShell\Modules.
2. Copy this folder into the modules folder
3. Check with `Get-Module ATAPHtmlReport -ListAvailable` if PowerShell detects the module.

Remark: The cmdlet `import-module` is not supported right now.
