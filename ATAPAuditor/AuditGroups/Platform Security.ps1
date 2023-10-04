$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
[AuditTest] @{
	Id = "SBD-001"
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
	Id = "SBD-002"
	Task = "Ensure the system is using SecureBoot."
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
	Id = "SBD-003"
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
	Id = "SBD-004"
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
	Id = "SBD-005"
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
			
			$state =  Get-CimInstance -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm
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
	Id = "SBD-006"
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
			$state =  Get-CimInstance -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm
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
	Id = "SBD-007"
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
			$state =  Get-CimInstance -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm
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
	Id = "SBD-008"
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