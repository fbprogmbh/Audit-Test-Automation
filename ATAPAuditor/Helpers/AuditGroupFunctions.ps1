Function Test-RegistryValue ($regkey, $name) {
    if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore) {
        $true
    } else {
        $false
    }
}

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
            $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
            if ($defStatus.AMRunningMode -ne "Normal") {
                # TODO: Eventlog
                Write-Host "ASR rules require Windows Defender Antivirus to be enabled."
                return $false
            }
            if (Test-Path -Path $Path) {
                return Test-RegistryValue $Path $Value
            } else {
                return $false
            }
        } catch {

        }
    }

}
