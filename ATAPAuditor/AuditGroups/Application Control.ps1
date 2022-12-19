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
    if($os -match "Windows 10 Enterprise" -or $os -match "Windows 11 Enterprise"){
        return $true
    }
    return $false
}

[AuditTest] @{
	Id = "SBD-040"
	Task = "Ensure Windows Defender Application Control (WDAC) is available."
	Test = {
        if(isWindows10Enterprise -eq $true){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Only supported on Windows 10 Enterprise."
            Status = "None"
        }
	}
}
[AuditTest] @{
	Id = "SBD-041"
	Task = "Ensure Windows Defender Application ID Service is running."
	Test = {
        if((Get-Service -Name APPIDSvc).Status -eq "Running"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "AppLocker is not running. Currently: $((Get-Service -Name APPIDSvc).Status)"
            Status = "False"
        }
	}
}
# [AuditTest] @{ Check for executable rules - windows installer rules - script rules - packaged app rules
# 	Id = "SBD-042"
# 	Task = "Ensure Windows Defender Application ID Service is running."
# 	Test = {
#         if((Get-Service -Name APPIDSvc).Status -eq "Running"){
#             return @{
#                 Message = "Compliant"
#                 Status = "True"
#             }
#         }
#         return @{
#             Message = "AppLocker is not running. Currently: $((Get-Service -Name APPIDSvc).Status)"
#             Status = "False"
#         }
# 	}
# }
