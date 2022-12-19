function Test-FirewallPaths {
    [CmdletBinding()]
    [OutputType([Object])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [String]
        $Path,
        [Parameter(Mandatory = $True)]
        [String]
        $Key,
        [Parameter(Mandatory = $True)]
        [Object]
        $ExpectedValue,
        [Parameter(Mandatory = $True)]
        [String]
        $ProfileType,
        [PSCustomObject]
        $Result = @{
            Message = "Registry value not found."
            Status  = "False"
        }
    )
    PROCESS {
        $regValue = Get-ItemProperty -ErrorAction SilentlyContinue `
            -Path $Path `
            -Name $Key `
        | Select-Object -ExpandProperty "$($Key)"
        # if regValue == expectedValue OR if the LogFilePath ends with .log
        if (($regValue -eq $ExpectedValue) -or (($Key -eq "LogFilePath") -and ($ExpectedValue -match "$ProfileType[a-z]*.log"))) {
            $Result = @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        # if regValue isnot empty AND regValue isnot expectedValue AND result is not True (yet)
        # This result is ranked #2 below "Compliant" and above "Registry value not found"
        if (($null -ne $regValue) -and ($regValue -ne $ExpectedValue) -and ($Result.Status -ne "True")) {
            $Result = @{
                Message = "Registry value is '$regValue'. Expected: $ExpectedValue"
                Status  = "False"
            }
        }
    }
    END {
        if ((Get-NetFirewallProfile -Name $ProfileType -ErrorAction SilentlyContinue).$Key -eq $expectedValue) {
            $Result = @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return $Result
    }
}

