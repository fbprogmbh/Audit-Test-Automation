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
    try {
        if ((Get-MpPreference -ErrorAction Ignore).Disablerealtimemonitoring) {
            return $false;
        }
    }
    catch {
        <#Do this if a terminating exception happens#>
    }
    try {
        $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
        if ($defStatus.AMRunningMode -eq "Normal") {
            return $true
        }      
    }
    catch {
        <#Do this if a terminating exception happens#>
    }
    try {
        if ((Get-WindowsFeature -Name Windows-Defender -ErrorAction Ignore).installed) {
            return $true
        }
    }
    catch {
        <#Do this if a terminating exception happens#>
    }
    return $false
}