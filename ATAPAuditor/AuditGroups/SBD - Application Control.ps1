$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
[AuditTest] @{
    Id = "SBD-072"
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
