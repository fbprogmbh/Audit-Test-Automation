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
function isWindows10Enterprise {
    $os = Get-ComputerInfo OsName
    if($os -match "Windows 10 Enterprise"){
        return $true
    }
    return $false
}

[AuditTest] @{
	Id = "SBD-034"
	Task = "Ensure system is configured to deny remote access via Terminal Services."
	Test = {
		$value = (Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
        if($value -eq 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "System is not configured to deny remote access via Terminal Services."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-035"
	Task = "Ensure system is configured to prevent RDP service."
	Test = {
		$value = (Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server").AllowRemoteRPC
        if($value -eq 0){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "System is not configured to prevent RDP service."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-036"
	Task = "Ensure NTLM Session Server Security settings are configured."
	Test = {
		$value = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0').NtlmMinServerSec
        if($value -eq 537395200){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "NTLM Session Server Security settings are configured. Currently: $($value)"
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-037"
	Task = "Ensure WinFW Service is running."
	Test = {
		$value = (Get-Service WinRM).status
        if($value -eq "Running"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "WinFW Service is not running. Currently: $($value)"
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-038"
	Task = "Ensure NetBios is set to 'Disabled'."
	Test = {
		$value = (Get-WmiObject -Class Win32_NetWorkAdapterConfiguration -Filter "IPEnabled=$true").TcpipNetbiosOptions
        if($value -eq 2){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "NetBios is 'Enabled'."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-039"
	Task = "Ensure SMBv1 is set to 'Disabled'."
	Test = {
		$value = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
        if($value -eq "Disabled"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "SMBv1 is Enabled."
            Status = "False"
        }
	}
}

