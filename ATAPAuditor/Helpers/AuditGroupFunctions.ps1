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

$sbdIndex = 1
function IncrementSecurityBaseDataCounter{
    return $sbdIndex++
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

function Get-LicenseStatus{
	$licenseStatus = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | where { $_.PartialProductKey } | select Description, LicenseStatus -ExpandProperty LicenseStatus)
	switch($licenseStatus){
		"0" {$lcStatus = "Unlicensed"}
		"1" {$lcStatus = "Licensed"}
		"2" {$lcStatus = "OOBGrace"}
		"3" {$lcStatus = "OOTGrace"}
		"4" {$lcStatus = "NonGenuineGrace"}
		"5" {$lcStatus = "Notification"}
		"6" {$lcStatus = "ExtendedGrace"}
	}
	return $lcStatus
}

function CheckWindefRunning {
    # for systems, won't work if server 
    try {
        $defStatus = (Get-MpComputerStatus -ErrorAction Ignore | Select-Object AMRunningMode)
        if ($defStatus.AMRunningMode -eq "Normal") {
            return $true
        }   
    }
    catch {
        <#Do this if a terminating exception happens#>
    }

    # for standalone systems, won't work if server 
    try {
        $defStatus = (Get-MpComputerStatus -ErrorAction Ignore)
        if ($defStatus.AMServiceEnabled -eq $true -and $defStatus.AntispywareEnabled -eq $true -and $defStatus.AntivirusEnabled -eq $true -and $defStatus.NISEnabled -eq $true -and $defStatus.RealTimeProtectionEnabled  -eq $true) {
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

function getListOfWeakCipherSuites {
    $listOfWeakCipherSuites = @(
        "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
        "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
        "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
        "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
        "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
        "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
        "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
        "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
        "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
        "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_DH_DSS_WITH_SEED_CBC_SHA",
        "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
        "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
        "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
        "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
        "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_PSK_WITH_AES_128_CCM",
        "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_DHE_PSK_WITH_AES_256_CCM",
        "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
        "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
        "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
        "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
        "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_CCM",
        "TLS_DHE_RSA_WITH_AES_128_CCM_8",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_CCM",
        "TLS_DHE_RSA_WITH_AES_256_CCM_8",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
        "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
        "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
        "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
        "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
        "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_DH_RSA_WITH_SEED_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
        "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
        "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
        "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
        "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
        "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
        "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
        "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
        "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
        "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
        "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
        "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
        "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
        "TLS_KRB5_WITH_IDEA_CBC_SHA",
        "TLS_PSK_DHE_WITH_AES_128_CCM_8",
        "TLS_PSK_DHE_WITH_AES_256_CCM_8",
        "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
        "TLS_PSK_WITH_AES_128_CBC_SHA",
        "TLS_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_PSK_WITH_AES_128_CCM",
        "TLS_PSK_WITH_AES_128_CCM_8",
        "TLS_PSK_WITH_AES_128_GCM_SHA256",
        "TLS_PSK_WITH_AES_256_CBC_SHA",
        "TLS_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_PSK_WITH_AES_256_CCM",
        "TLS_PSK_WITH_AES_256_CCM_8",
        "TLS_PSK_WITH_AES_256_GCM_SHA384",
        "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
        "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
        "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
        "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
        "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
        "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
        "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
        "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
        "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_AES_128_CCM",
        "TLS_RSA_WITH_AES_128_CCM_8",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_RSA_WITH_AES_256_CCM",
        "TLS_RSA_WITH_AES_256_CCM_8",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
        "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
        "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
        "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_RSA_WITH_IDEA_CBC_SHA",
        "TLS_RSA_WITH_SEED_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
        "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
        "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
        "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
    )
    return $listOfWeakCipherSuites
}

function getListOfInsecureCipherSuites {
    $listOfInsecureCipherSuites = @(
        "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
        "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
        "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
        "TLS_DH_anon_WITH_AES_256_CBC_SHA",
        "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
        "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
        "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
        "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
        "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
        "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
        "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
        "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_DH_anon_WITH_DES_CBC_SHA",
        "TLS_DH_anon_WITH_RC4_128_MD5",
        "TLS_DH_anon_WITH_SEED_CBC_SHA",
        "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DH_DSS_WITH_DES_CBC_SHA",
        "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        "TLS_DHE_PSK_WITH_NULL_SHA",
        "TLS_DHE_PSK_WITH_NULL_SHA256",
        "TLS_DHE_PSK_WITH_NULL_SHA384",
        "TLS_DHE_PSK_WITH_RC4_128_SHA",
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_RSA_WITH_DES_CBC_SHA",
        "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DH_RSA_WITH_DES_CBC_SHA",
        "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_anon_WITH_NULL_SHA",
        "TLS_ECDH_anon_WITH_RC4_128_SHA",
        "TLS_ECDH_ECDSA_WITH_NULL_SHA",
        "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_PSK_WITH_NULL_SHA",
        "TLS_ECDHE_PSK_WITH_NULL_SHA256",
        "TLS_ECDHE_PSK_WITH_NULL_SHA384",
        "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
        "TLS_ECDHE_RSA_WITH_NULL_SHA",
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        "TLS_ECDH_RSA_WITH_NULL_SHA",
        "TLS_ECDH_RSA_WITH_RC4_128_SHA",
        "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
        "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
        "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
        "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
        "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
        "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
        "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
        "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
        "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
        "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
        "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
        "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
        "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
        "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
        "TLS_KRB5_WITH_DES_CBC_MD5",
        "TLS_KRB5_WITH_DES_CBC_SHA",
        "TLS_KRB5_WITH_IDEA_CBC_MD5",
        "TLS_KRB5_WITH_RC4_128_MD5",
        "TLS_KRB5_WITH_RC4_128_SHA",
        "TLS_NULL_WITH_NULL_NULL",
        "TLS_PSK_WITH_NULL_SHA",
        "TLS_PSK_WITH_NULL_SHA256",
        "TLS_PSK_WITH_NULL_SHA384",
        "TLS_PSK_WITH_RC4_128_SHA",
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        "TLS_RSA_PSK_WITH_NULL_SHA",
        "TLS_RSA_PSK_WITH_NULL_SHA256",
        "TLS_RSA_PSK_WITH_NULL_SHA384",
        "TLS_RSA_PSK_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_DES_CBC_SHA",
        "TLS_RSA_WITH_NULL_MD5",
        "TLS_RSA_WITH_NULL_SHA",
        "TLS_RSA_WITH_NULL_SHA256",
        "TLS_RSA_WITH_RC4_128_MD5",
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_SHA256_SHA256",
        "TLS_SHA384_SHA384",
        "TLS_SM4_CCM_SM3",
        "TLS_SM4_GCM_SM3"
    )
    return $listOfInsecureCipherSuites
}