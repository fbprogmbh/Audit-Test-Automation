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

## Usage

To generate a report, use `Get-ATAPHtmlReport`. However, you will need to provide the *path* where the report will be stored, the report *title*, the audit *module name*, and what hardening standard it is *based on*. To give the report a little bit more context, about the computer the report was generated on, you can provide your own *host information* (a table at the beginning of the report).

The main content of the report is structured into *sections*. A section must have a *title*, but can also include a *description*, a table of *AuditInfos*, and *SubSections*. AuditInfos represent a single audit test with an *Id*, *Task*, *Message*, and *Audit* that states whether the the system completed the test with True, False, Warning, or None.

For example, a simple section could look like this:

```powershell
[hashtable[]]$reportSections = @()

$reportSections += @{
    Title = "Section 1"
    Description = "All tests from section 1 of the my audit benchmark is here"
    AuditInfos = @(
        (New-Object -TypeName AuditInfo -Property @{
            Id      = "1.1"
            Task    = "Ensure something is set"
            Message = "All Good"
            Audit   = [AuditStatus]::True
        }),
        (New-Object -TypeName AuditInfo -Property @{
            Id      = "1.2"
            Task    = "Ensure something else is set"
            Message = "Result could be better"
            Audit   = [AuditStatus]::Warning
        })
    )
}
```

A more complicated section could look like this.

```powershell
$reportSections += @{
    Title = "Section 2"
    SubSections = @(
        @{
            Title = "First subsection of section 2"
            AuditInfos = @(
                (New-Object -TypeName AuditInfo -Property @{
                    Id      = "2.1.1"
                    Task    = "Ensure something"
                    Message = "Not entirely false"
                    Audit   = [AuditStatus]::Warning
                }),
                (New-Object -TypeName AuditInfo -Property @{
                    Id      = "2.1.2"
                    Task    = "Ensure something entirely different"
                    Message = "All good"
                    Audit   = [AuditStatus]::True
                })
            )
        },
        @{
            Title = "Second subsection of section 2"
            AuditInfos = @(
                (New-Object -TypeName AuditInfo -Property @{
                    Id      = "2.2.1"
                    Task    = "Ensure something way different"
                    Message = "Oops, something went wrong!"
                    Audit   = [AuditStatus]::False
                })
            )
        }
    )
}
```

Tied up, the full usage of the `Get-ATAPHtmlReport` function could look like this:

```powershell
Get-ATAPHtmlReport `
    -Path $Path `
    -Title "My Audit Benchmark" `
    -ModuleName "MyAuditBenchmark" `
    -BasedOn "My Audit Benchmarks Benchmark vX.X.X.X" `
    -HostInformation (Get-MyHostInformation) `
    -Sections $reportSections
```

## Troubleshooting
Using `Import-Module` instead of installing might not work. Please follow the outlined steps above.