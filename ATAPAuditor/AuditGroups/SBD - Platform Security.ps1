$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
[AuditTest] @{
	Id = "SBD-101"
	Task = "Ensure the system is booting in 'UEFI' mode."
	Test = {
		if (isWindows8OrNewer) {
			$status = switch ($env:firmware_type) {
				"UEFI" {
					@{
						Message = "Compliant"
						Status = "True"
					}
				}
				"Legacy" {
					@{
						Message = "System is booting using 'Legacy' mode."
						Status = "False"
					}
				}
				Default {
					@{
						Message = "Unknown boot mode"
						Status = "False"
					}
				}
			}
			return $status
		}
		else {
			if ((bcdedit | findstr -i path | findstr -i winload.efi).Count -ge 1) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			elseif (((bcdedit | findstr -i path | findstr -i winload.exe).Count -ge 1)) {
				return @{
					Message = "System is booting using 'Legacy' mode."
					Status = "False"
				}
			}
			else {
				return @{
					Message = "Unknown boot mode"
					Status = "False"
				}
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-102"
	Task = "Virtualization Based Security: Ensure the system is using SecureBoot."
	Test = {
		if (isWindows8OrNewer) {
			try {
				$status = switch ($env:firmware_type) {
					"UEFI" {
						$obj = Confirm-SecureBootUEFI
					}
					"Legacy" {
						return @{
							Message = "System is booting using 'Legacy' mode. SecureBoot not supported."
							Status = "False"
						}
					}
					Default {
						return @{
							Message = "Unknown boot mode"
							Status = "False"
						}
					}
				}
			}
			catch [UnauthorizedAccessException] {
				return @{
					Message = "Permission Denied"
					Status = "Error"
				}
			}
			$status = switch ($obj) {
				$true {
					@{
						Message = "Compliant"
						Status = "True"
					}
				}
				$false {
					@{
						Message = "SecureBoot is supported but disabled."
						Status = "False"
					}
				}
				Default {
					@{
						Message = "SecureBoot is not supported or system is in non-UEFI mode."
						Status = "False"
					}
				}
			}
			return $status
		}
		else {
			return @{
				Message = "System does not support this feature (Windows 8 or newer required)."
				Status = "None"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-103"
	Task = "Ensure the TPM Chip is 'present'."
	Test = {
		$hasTpm = hasTPM
		if (($null -eq $hasTpm) -or ($false -eq $hasTpm)) {
			return @{
				Message = "No TPM Chip detected."
				Status = "False"
			}
		}
		if (isWindows8OrNewer) {
			$obj = (Get-Tpm).TpmPresent
			if ($obj -isnot [Boolean]) {
				return @{
					Message = "Cannot get 'present' status of TPM."
					Status = "Error"
				}
			}
			$status = switch ($obj) {
				$true {
					@{
						Message = "Compliant"
						Status = "True"
					}
				}
				$false {
					@{
						Message = "The TPM Chip is not 'present'."
						Status = "False"
					}
				}
			}
			return $status
		}
		else {
			# Get any property to see if a TPM is present
			if (win7NoTPMChipDetected) {
				return @{
					Message = "No TPM Chip detected."
					Status = "False"
				}
			} else {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-104"
	Task = "Ensure the TPM Chip is 'ready'."
	Test = {
		$hasTpm = hasTPM
		if (($null -eq $hasTpm) -or ($false -eq $hasTpm)) {
			return @{
				Message = "No TPM Chip detected."
				Status = "False"
			}
		}
		if (isWindows8OrNewer) {
			$obj = (Get-Tpm).TpmReady
			if ($obj -isnot [Boolean]) {
				return @{
					Message = "Cannot get 'ready' status of TPM."
					Status = "Error"
				}
			}
			$status = switch ($obj) {
				$true {
					@{
						Message = "Compliant"
						Status = "True"
					}
				}
				$false {
					@{
						Message = "The TPM Chip is not 'ready'."
						Status = "False"
					}
				}
			}
			return $status
		}
		else {
			if (win7NoTPMChipDetected) {
				return @{
					Message = "No TPM Chip detected."
					Status = "False"
				}
			} else {
				return @{
					Message = "System does not expose a 'ready' status"
					Status = "None"
				}
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-105"
	Task = "Ensure the TPM Chip is 'enabled'."
	Test = {
		$hasTpm = hasTPM
		if (($null -eq $hasTpm) -or ($false -eq $hasTpm)) {
			return @{
				Message = "No TPM Chip detected."
				Status = "False"
			}
		}
		if (isWindows8OrNewer) {
			
			$state =  Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm
			if ($state.IsEnabled_InitialValue -eq $true) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			return @{
				Message = "The TPM Chip is not 'enabled'."
				Status = "False"
			}
		}
		else {
			if (win7NoTPMChipDetected) {
				return @{
					Message = "No TPM Chip detected."
					Status = "False"
				}
			}
			if (Get-CimInstance -ClassName Win32_Tpm -Namespace root\cimv2\security\microsofttpm | Select-Object -ExpandProperty IsEnabled_InitialValue) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			else {
				return @{
					Message = "The TPM Chip is not 'enabled'."
					Status = "False"
				}
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-106"
	Task = "Ensure the TPM Chip is 'activated'."
	Test = {
		$hasTpm = hasTPM
		if (($null -eq $hasTpm) -or ($false -eq $hasTpm)) {
			return @{
				Message = "No TPM Chip detected."
				Status = "False"
			}
		}
		if (isWindows8OrNewer) {
			$state =  Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm
			if ($state.IsActivated_InitialValue -eq $true) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			return @{
				Message = "The TPM Chip is not 'enabled'."
				Status = "False"
			}
		}
		else {
			if (win7NoTPMChipDetected) {
				return @{
					Message = "No TPM Chip detected."
					Status = "False"
				}
			}
			if (Get-CimInstance -ClassName Win32_Tpm -Namespace root\cimv2\security\microsofttpm | Select-Object -ExpandProperty IsActivated_InitialValue) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			else {
				return @{
					Message = "The TPM Chip is not 'activated'."
					Status = "False"
				}
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-107"
	Task = "Ensure the TPM Chip is 'owned'."
	Test = {
		$hasTpm = hasTPM
		if (($null -eq $hasTpm) -or ($false -eq $hasTpm)) {
			return @{
				Message = "No TPM Chip detected."
				Status = "False"
			}
		}
		if (isWindows8OrNewer) {
			$state =  Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm
			if ($state.IsOwned_InitialValue -eq $true) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			return @{
				Message = "The TPM Chip is not 'enabled'."
				Status = "False"
			}
		}
		else {
			if (win7NoTPMChipDetected) {
				return @{
					Message = "No TPM Chip detected."
					Status = "False"
				}
			}
			if (Get-CimInstance -ClassName Win32_Tpm -Namespace root\cimv2\security\microsofttpm | Select-Object -ExpandProperty IsOwned_InitialValue) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			else {
				return @{
					Message = "The TPM Chip is not 'owned'."
					Status = "False"
				}
			}
			
		}
	}
}
[AuditTest] @{
	Id = "SBD-108"
	Task = "Ensure the TPM Chip is implementing specification version 2.0 or higher."
	Test = {
		$hasTpm = hasTPM
		if (($null -eq $hasTpm) -or ($false -eq $hasTpm)) {
			return @{
				Message = "No TPM Chip detected."
				Status = "False"
			}
		}
		# get array of implemented spec versions
		$obj = (Get-CimInstance -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SpecVersion)
		if ($obj -eq $null) {
			return @{
				Message = "No TPM Chip detected."
				Status = "False"
			}
		}
		# get main spec version (first element)
		$obj = $obj.split(', ')[0]

		if ($obj -ge 2.0) {
			return @{
				Message = "Compliant"
				Status = "True"
			}
		}
		elseif ($obj -gt 0) {
			return @{
				Message = "Specification version lower than 2.0 found."
				Status = "Warning"
			}
		} else {
			return @{
				Message = "No implemented specification version found."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-109"
	Task = "Virtualization Based Security: Ensure Virtualization Based Security is enabled and running."
	Test = {
		$isWindows10OrNewer = isWindows10OrNewer
		if($isWindows10OrNewer -eq $false){
			return @{
				Message = "System does not support this feature (Windows 10 or newer required)."
				Status = "None"
			}
		}
		$obj = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
		$status = switch ($obj) {
			{$PSItem -eq 2} {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			{$PSItem -eq 1} {
				return @{
					Message = "VBS is activated but not running."
					Status = "False"
				}
			}
			{$PSItem -eq 0} {
				return @{
					Message = "VBS is not activated."
					Status = "False"
				}
			}
			default {
				return @{
					Message = "Cannot get the VBS status."
					Status = "Error"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-110"
	Task = "Virtualization Based Security: Ensure Hypervisor-protected Code Integrity (HVCI) is running."
	Test = {
		$isWindows10OrNewer = isWindows10OrNewer
		if($isWindows10OrNewer -eq $false){
			return @{
				Message = "System does not support this feature (Windows 10 or newer required)."
				Status = "None"
			}
		}
		if ((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning -contains 2) {
			return @{
				Message = "Compliant"
				Status = "True"
			}
		}
		else {
			return @{
				Message = "HVCI is not running."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-111"
	Task = "Virtualization Based Security: Ensure Credential Guard is running."
	Test = {
		$value = isWindows10OrNewer
		if($value -eq $false){
			return @{
				Message = "System does not support this feature (Windows 10 or newer required)."
				Status = "None"
			}
		}
		$systemSKU = (Get-CimInstance Win32_OperatingSystem).Caption
		$supportedSKUs = @("Windows Enterprise", "Windows Education", "Windows Server")

		$system = $systemSKU -replace "\d\s*", ""
		$system = $system -replace "Microsoft ", ""
		if($supportedSKUs.Contains($system)){
			if ((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning -contains 1) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			else {
				return @{
					Message = "Credential Guard is not running."
					Status = "False"
				}
			}
		}
		else{
			if ((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesConfigured -contains 1) {
				return @{
					Message = "Credential Guard is configured but not running, due to incompatibility with $($systemSKU) <br/>See Microsoft documentation for further information: <a href='https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/#windows-edition-and-licensing-requirements' target='_blank'>Here</a>"
					Status = "False"
				}
			}
			else {
				return @{
					Message = "Credential Guard is not configured."
					Status = "False"
				}
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-112"
	Task = "Virtualization Based Security: Ensure Security Services are running."
	Test = {
		$value = isWindows10OrNewer
		if($value -eq $false){
			return @{
				Message = "System does not support this feature (Windows 10 or newer required)."
				Status = "None"
			}
		}
		$serviceRunningIDs = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
		if ($serviceRunningIDs -contains 0) {
			return @{
				Message = "No Device Guard security services are running."
				Status = "False"
			}
		} 
		if ($serviceRunningIDs -contains 1) {
			$message += "Credential Guard"
		}
		if ($serviceRunningIDs -contains 2) {
			if (![string]::IsNullOrEmpty($message)) {
				$message += ", "
			}
			$message += "Memory Integrity (HVCI)"
		}
		if ($serviceRunningIDs -contains 3) {
			if (![string]::IsNullOrEmpty($message)) {
				$message += ", "
			}
			$message += "System Guard Secure Launch"
		}
		if ($serviceRunningIDs -contains 4) {
			if (![string]::IsNullOrEmpty($message)) {
				$message += ", "
			}
			$message += "SMM Firmware Measurement"
		}
		if ($serviceRunningIDs -contains 5) {
			if (![string]::IsNullOrEmpty($message)) {
				$message += ", "
			}
			$message += "Kernel-mode Hardware-enforced Stack Protection"
		}
		if ($serviceRunningIDs -contains 6) {
			if (![string]::IsNullOrEmpty($message)) {
				$message += ", "
			}
			$message += "Kernel-mode Hardware-enforced Stack Protection is configured in Audit mode"
		}
		if ($serviceRunningIDs -contains 7) {
			if (![string]::IsNullOrEmpty($message)) {
				$message += ", "
			}
			$message += "Hypervisor-Enforced Paging Translation"
		} 
		return @{
			Message = "$message are running on Device Guard as services."
			Status = "True"
		}
	}
}