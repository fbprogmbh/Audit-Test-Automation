# Begin Helper for version control
function isWindows8OrNewer {
	return ([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,2))
}
function isWindows81OrNewer {
	return ([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,3))
}
function isWindows10OrNewer {
	return ([Environment]::OSVersion.Version -ge (New-Object 'Version' 10,0))
}
function win7NoTPMChipDetected {
	return (Get-CimInstance -ClassName Win32_Tpm -Namespace root\cimv2\security\microsofttpm | Select-Object -ExpandProperty IsActivated_InitialValue) -eq $null
}
function hasTPM {
	try {
		$obj = (Get-Tpm).TpmPresent
	} catch {
		return $null
	}
	return $obj
}
# End Helper for version control
function isWindows10Enterprise {
    $os = Get-ComputerInfo OsName
    if($os -match "Windows 10 Enterprise" -or $os -match "Windows 11 Enterprise"){
        return $true
    }
    return $false
}

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

#Returns Hyper-V status
function CheckHyperVStatus {
    return (Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V").State
}

function CheckLicense {
    # 0=Unlicensed
    # 1=Licensed
    # 2=OOBGrace
    # 3=OOTGrace
    # 4=NonGenuineGrace
    # 5=Notification
    # 6=ExtendedGrace
    return (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | where { $_.PartialProductKey } | select Description, LicenseStatus -ExpandProperty LicenseStatus)
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
