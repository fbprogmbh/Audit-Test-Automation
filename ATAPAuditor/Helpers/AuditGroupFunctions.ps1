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

function CheckWindefRunning {
    # for standalone systems, won't work if server 
    try {
        $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
        if ($defStatus.AMRunningMode -eq "Normal") {
            return $true
        }   
    }
    catch {
        <#Do this if a terminating exception happens#>
    }

    # for servers, won't work if standalone system
    try {
        if ((Get-WindowsFeature -Name Windows-Defender -ErrorAction Ignore).installed) {
            if ((Get-Service -Name windefend -ErrorAction Ignore).Status -eq "Running") {
                return $true
            }
        }
    }
    catch {
        <#Do this if a terminating exception happens#>
    }
    
    return $false
}

function CheckForActiveAV {
    $result = $false
    $av = Get-AntiVirusStatus
    foreach ($a in $av) {
        if (($a.'Definition Status') -eq "Enabled") {
            $result = $true;
        }
    }
    return $result
}

# only works for desktop workstations, not servers (except Windows XP and older)
function Get-AntiVirusStatus {
    try {
        $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ComputerName $env:computername -ErrorAction Stop
    }
    catch [System.Management.ManagementException] {
        <#Do this if a terminating exception happens#>
    }

    $result = @()
    foreach($AntiVirusProduct in $AntiVirusProducts){

        $hex = '0x{0:x}' -f $AntiVirusProduct.productState
        $avstatus = $hex.Substring(3,2)
        $defstatus = "Unknown"
        if (($avstatus -eq "00") -or ($avstatus -eq "01")) {
            $defstatus = "Disabled"
        }
        if (($avstatus -eq "10") -or ($avstatus -eq "11")) {
            $defstatus = "Enabled"
        }

        $avupdated = $hex.Substring(5,2)
        $avupdatestatus = "Unknown"
        if ($avupdated -eq ("10")) {
            $avupdatestatus = "Not Up-to-date"
        }
        if ($avupdated -eq ("00")) {
            $avupdatestatus = "Up-to-date"
        }

        # hashtable for av status
        $ht = @{}
        $ht.Name = $AntiVirusProduct.displayName
        $ht.'Definition Status' = $defstatus
        $ht.'Update Status' = $avupdatestatus

        # add new hashtable to result
        $result += New-Object -TypeName PSObject -Property $ht 
    }
    return $result
} 