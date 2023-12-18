$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
[AuditTest] @{
    Id = "SBD-072"
	Task = "Ensure Windows Defender Application Control (WDAC) is available."
	Test = {
        $os = Get-ComputerInfo OsName
        $isHomeVersion = $os -match "Home"
        $windowsServerVersions = @(
            "Windows Server 2016",
            "Windows Server 2019",
            "Windows Server 2022"
        )
        $isServer2016newer = $windowsServerVersions -contains $os
        if(!($isHomeVersion -eq $true) -and !($isServer2016newer -eq $true)){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Only supported on Windows 10 and newer (except Home Editions), as well as Windows Server 2016 and newer."
            Status = "None"
        }
	}
}
[AuditTest] @{
	Id = "SBD-073"
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
