# CIS IIS 8 Audit Script
_based on CIS Microsoft IIS 8 Benchmarks v1.5.0 12-30-2016_

## Requirements
This script uses Cmdlets from the IISAdministration module  which is *not* included in a IIS 8 installation. Please download the module first and put it into the Windows PowerShell folder.
If you have a internet connection on your machine you can simply open an elevated PowerShell and type

```Powershell
Install-Module IISAdministration
```

to install the module


## Loading the IIS Audit module

When loading the module, make sure that the manifest is loaded as well. Do not include the file extension of the module. 

```Powershell
Import-Module -Name .\IIS8Audit -Verbose
```

This is important because the manifest tells Powershell about the assemblies and modules that the module requires.

## Sample report

You can find a sample report in the [Sample](Sample/sample_report.html) folder.
