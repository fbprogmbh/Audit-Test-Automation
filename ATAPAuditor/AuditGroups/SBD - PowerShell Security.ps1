[AuditTest] @{
	Id = "SBD-301"
	Task = "Ensure PowerShell Version is set to version 5 or higher."
	Test = {
		if ($PSVersionTable.PSVersion.Major -ge 5) {
            return @{
                Message = "Compliant"
                Status = "True"
            }
		}
        return @{
            Message = "PowerShell version is lower than 5. Current Version: $($PSVersionTable.PSVersion)"
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-302"
	Task = "Ensure PowerShell Version 2 is uninstalled."
	Test = {
        $ps2Found = $false
        $messages = "The following PS2-related features are enabled:"

        $PSV2State = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State
        if ($PSV2State -ne "Disabled") {
            $messages += "<br>Windows PowerShell 2.0 Engine"
            $ps2Found = $true
        }

        $os = Get-CimInstance Win32_OperatingSystem
        if ($os.ProductType -eq 1) {
            $PSRootState = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State
            if ($PSRootState -ne "Disabled") {
                $messages += "<br>Windows PowerShell 2.0"
                $ps2Found = $true
            }
        }

        if ($ps2Found -eq $true) {
            return @{
                Message = $messages
                Status = "False"
            }
        }

        return @{
            Message = "Compliant"
            Status = "True"
        }
	}
}
[AuditTest] @{
	Id = "SBD-303"
	Task = "Ensure PowerShell is set to configured to use Constrained Language."
	Test = {
		$languageMode = $ExecutionContext.SessionState.LanguageMode
        if($languageMode -eq "ConstrainedLanguage"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Language Mode is not set to 'Constrained Language'. Current configuration: $($languageMode)"
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-304"
	Task = "Ensure Execution policy is set to AllSigned / RemoteSigned."
	Test = {
		$execPolicy = Get-ExecutionPolicy
        if($execPolicy -eq "AllSigned" -or $execPolicy -eq "RemoteSigned"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Execution Policy is not set to AllSigned / Remote Signed. Current configuration: $($execPolicy)"
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-305"
	Task = "Ensure PowerShell Commandline Audting is set to 'Enabled'."
	Test = {
		$value = (Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
        if($value -eq 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "PowerShell Commandline Auditing is not set to 'Enabled'."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-306"
	Task = "Ensure PowerShell Module Logging is set to 'Enabled'."
	Test = {
		$value = (Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging
        if($value -eq 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "PowerShell Module Logging is not set to 'Enabled'."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-307"
	Task = "Ensure PowerShell ScriptBlockLogging is set to 'Enabled'."
	Test = {
		$value = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        if($value -eq 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "PowerShell ScriptBlockLogging is not set to 'Enabled'."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-308"
	Task = "Ensure PowerShell ScriptBlockInvocationLogging is set to 'Enabled'."
	Test = {
		$value = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging
        if($value -eq 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "PowerShell ScriptBlockInvocationLogging is not set to 'Enabled'."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-309"
	Task = "Ensure PowerShell Transcripting is set to 'Enabled'."
	Test = {	
		$value = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting
        if($value -eq 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "PowerShell Transcripting is not set to 'Enabled'."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-310"
	Task = "Ensure PowerShell InvocationHeader is set to 'Enabled'."
	Test = {	
        $value = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader
        if($value -eq 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "PowerShell InvocationHeader is not set to 'Enabled'."
            Status = "False"
        }
	}
}
[AuditTest] @{
	Id = "SBD-311"
	Task = "Ensure PowerShell ProtectedEventLogging is set to 'Enabled'."
	Test = {
		$value = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging
        if($value -eq 1){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "PowerShell ProtectedEventLogging is not set to 'Enabled'."
            Status = "False"
        }
    }
}
