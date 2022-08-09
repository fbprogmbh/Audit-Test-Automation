# helper
function Test-RiskScoreQuality {
    [CmdletBinding()]
    [OutputType([RiskQualityReport[]])]

    $tests = . "$RootPath\RiskScore\RiskScoreTests.ps1"

    foreach ($test in $tests) {
        if (test.Status -EQ "Failed") {
            $resultTable.Failed += 1
        }
        if (test.Status -EQ "Success") {
            $resultTable.Success += 1
        }
    }

    Write-Output ([RiskQualityReport]@{
            TestTable   = $tests
            ResultTable = $resultTable
            EndResult   = Get-RiskScoreEndResult($resultTable)
        })
}

function Get-RiskScoreEndResult {
    [CmdletBinding()]
    [OutputType([string])]

    param (
        [Parameter(Mandatory = $true)]
        [array]
        $resultTable
    )

    $f = $resultTable.Failed
    if ($f -lt 3) {
        return "Low"
    }
    if ($f -ge 3 -and $f -le 4) {
        return "Medium"
    }
    if ($f -eq 5) {
        return "High"
    }
    if ($f -ge 6) {
        return "Critical"
    }
}   }
    if ($f -ge 6) {
        return "Critical"
    }
}