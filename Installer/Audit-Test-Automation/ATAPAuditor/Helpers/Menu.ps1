# Get the report names from the files in the Module folder
function Get-Reports {
    # Get the path to the module
    $atapFile = (Get-Module -ListAvailable ATAPAuditor).Path
    if ($atapFile.Count -gt 1) {
        $atapFile = $atapFile[0] # use the first result if there are several
    } elseif ($atapFile.Count -eq 0) {
        Write-Host "The ATAP module could not be found."
        pressAnyKeyToQuit
        Exit
    }

    # find all *.ps1 report files
    $atapDir = Split-Path -parent $atapFile
    $reportsDir = Join-Path -Path $atapDir -ChildPath "Reports"
    $reportFiles = Get-ChildItem -Path "$reportsDir\*.ps1" -Recurse

    # Build a dictionary from the file names without the extension
    $i = 1
    $reports = [ordered]@{}
    foreach ($reportName in $reportFiles) {
        $reports.add([string]$i, $reportName.BaseName)
        $i++
    }
    return $reports
}

# present a menu based on the dict given as argument
function Show-Menu {
    param (
        [System.Collections.Specialized.OrderedDictionary]$reports
    )
    Clear-Host
    Write-Host "============== AuditTAP Reports ==============`n"
    $padCount = ([string]$reports.Count).Length
    foreach ($item in $reports.GetEnumerator()) {
        Write-Host (' {0}: {1}' -f $item.Key.PadLeft($padCount, ' '), $item.Value)
    }
    Write-Host ""
}


function askSelection {
    param (
        [System.Collections.Specialized.OrderedDictionary]$reports
    )
    $retry = $false
    :loop while ($true) {
        # show menu and ask the user for a selection (or multiple)
        Show-Menu $reports
        if ($retry) {
            [string]$selection = Read-Host "Invalid selection. Please try again`nYou can select multiple reports by comma separating the numbers"
        } else {
            [string]$selection = Read-Host "Please choose a report to run`nYou can select multiple reports by comma separating the numbers"
        }

        # sanitize input data
        $selection = $selection -replace '\s',''
        $selection = $selection.Trim(',')
        $selectionArray = $selection.Split(",")
        $selectionArray = $selectionArray | Select-Object -Unique

        # Check if requested reports are valid / actually present
        $reportsValid = @()
        foreach ($i in $selectionArray) {
            if (!$reports.Contains($i)) {
                Write-Host "Report $i does not exist"
                $retry = $true
                Continue loop
            } else {
                $reportsValid += $reports[$i]
            }
        }
        
        # return the list of valid reports as an array of strings
        return $reportsValid
    }
}

function runReports {
    param (
        [string[]]$report
    )
    Clear-Host
    Import-Module -Name ATAPAuditor -Force
    foreach ($i in $report) {
        Write-Host "Running report: $i"
        Save-ATAPHtmlReport -ReportName $i -Force
        Write-Host ""
    }
}

function isAdmin {
    $unixOS = [System.Environment]::OSVersion.Platform -eq 'Unix'
	if ($unixOS) {
        return ($(id -u) -eq 0)
    } else {
        return ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')
    }
}

function pressAnyKeyToQuit {
    if ($psISE) {
        Return
    }
    Write-Host "Press any key to quit"
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

if (!(isAdmin)) {
    Write-Host "Please run as administrator`n"
    pressAnyKeyToQuit
} else {
    $reports = Get-Reports
    Show-Menu $reports
    $sel = askSelection $reports
    runReports $sel

    if ([System.Environment]::OSVersion.Platform -eq 'Unix') {
        if (($env:XDG_SESSION_TYPE -eq 'tty') -or ($null -eq $env:SUDO_USER)) {
            # 1. reason to return: no graphical environment to open the file explorer
            # 2. reason to return: we do not want to open the file explorer as root
            Return
        }
    }

    [string]$action = Read-Host "Do you want to open the output directory? (y/N)"
    if ($action -eq 'y') {
        if ($null -eq $env:ATAPReportPath) {
            $outPath = [Environment]::GetFolderPath('MyDocuments') | Join-Path -ChildPath 'ATAPReports'
        } else {
            $outPath = $env:ATAPReportPath
        }
        if (Test-Path -Path $outPath) {
            if ([System.Environment]::OSVersion.Platform -eq 'Unix') {
                su $env:SUDO_USER -c "xdg-open $outPath"
            } else {
                explorer.exe $outPath
            }
        }
    }
}
