#Helper function for 'Test-ASRRules'
Function Test-RegistryValue ($regkey, $name) {
    if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore) {
        $true
    }
    else {
        $false
    }
}

#This function is needed in AuditGroups, which check both paths of ASR-Rules.
function Test-ASRRules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Path,
        [Parameter(Mandatory = $true)]
        [String] $Value
    )

    process {
        try {
            if (Test-Path -Path $Path) {
                return Test-RegistryValue $Path $Value
            }
            else {
                return $false
            }
        }
        catch {

        }
    }

}

#Returns Hyper-V status
function CheckHyperVStatus {
    return (Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V").State
}

function IsInstalled-WindowsDefender {
    $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
    if ($defStatus.AMRunningMode -eq "Normal") {
        return $true
    }      
    if ((Get-WindowsFeature -Name Windows-Defender -ErrorAction Ignore).installed) {
        return $true
    }
    return $false
}

function Test-MultiplePaths {
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
        # if regValue == expectedValue
        if (($regValue -eq $ExpectedValue)) {
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
        return $Result
    }
}
