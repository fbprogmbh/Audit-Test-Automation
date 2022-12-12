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
        
        if (($regValue -eq $ExpectedValue)) {
            $Result = @{
                Message = "Compliant"
                Status  = "True"
            }
        }
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

