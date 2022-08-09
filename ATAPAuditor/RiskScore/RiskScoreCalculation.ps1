# helper for RiskQualityReport
function Test-RiskScoreQuality {
    [CmdletBinding()]
    [OutputType([RiskQualityReport[]])]

    param (
        [Parameter()]
        [ResultTable[]]
        $resultTable
    )

    $tests = . "$RootPath\RiskScore\RiskScoreTests.ps1"

    foreach ($test in $tests) {
        if (test.Status -EQ "Failed") {
            $resultTable.Failed += 1
        }
        if (test.Status -EQ "Success") {
            $resultTable.Success += 1
        }
    }

    return ([RiskQualityReport]@{
            TestTable   = $tests
            ResultTable = $resultTable
            Endresult   = Get-RiskScoreEndResult($resultTable)
        })
}

# helper for EndResult
function Get-RiskScoreEndResult {
    [CmdletBinding()]
    [OutputType([string])]

    param (
        [Parameter(Mandatory = $true)]
        [ResultTable[]]
        $resultTable
    )

    $result = "Unknown"
    
    $f = $resultTable.Failed
    if ($f -lt 3) {
        $result = "Low"
    }
    if ($f -ge 3 -and $f -le 4) {
        $result = "Medium"
    }
    if ($f -eq 5) {
        $result = "High"
    }
    if ($f -ge 6) {
        $result = "Critical"
    }
    return $result
}