[AuditTest] @{
	Id = "SBD-001"
	Task = "Ensure the system is booting in 'UEFI' mode."
	Test = {	
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
}
[AuditTest] @{
	Id = "SBD-002"
	Task = "Ensure the system is using SecureBoot."
	Test = {
		try {
			$obj = Confirm-SecureBootUEFI
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
}
[AuditTest] @{
	Id = "SBD-003"
	Task = "Ensure the TPM Chip is 'present'."
	Test = {
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
}
[AuditTest] @{
	Id = "SBD-004"
	Task = "Ensure the TPM Chip is 'ready'."
	Test = {
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
}
[AuditTest] @{
	Id = "SBD-005"
	Task = "Ensure the TPM Chip is 'enabled'."
	Test = {
		$obj = (Get-Tpm).TpmEnabled
		if ($obj -isnot [Boolean]) {
			return @{
				Message = "Cannot get 'enabled' status of TPM."
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
					Message = "The TPM Chip is not 'enabled'."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-006"
	Task = "Ensure the TPM Chip is 'activated'."
	Test = {
		$obj = (Get-Tpm).TpmActivated
		if ($obj -isnot [Boolean]) {
			return @{
				Message = "Cannot get 'activated' status of TPM."
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
					Message = "The TPM Chip is not 'activated'."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-007"
	Task = "Ensure the TPM Chip is 'owned'."
	Test = {
		$obj = (Get-Tpm).TpmOwned
		if ($obj -isnot [Boolean]) {
			return @{
				Message = "Cannot get 'owned' status of TPM."
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
					Message = "The TPM Chip is not 'owned'."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-008"
	Task = "Ensure the TPM Chip is implementing the specification version 2.0 or higher."
	Test = {
		# get array of implemented spec versions
		$obj = (Get-CimInstance -Class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SpecVersion)
		if ($obj -eq $null) {
			return @{
				Message = "Permission Denied"
				Status = "Error"
			}
		}
		# get main spec version (first element)
		$obj = $obj.replace(' ','').split(',')[0]

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
				Message = "No TPM implemented specification version found."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-009"
	Task = "Get the count of local users on the system."
	Test = {	
		$status = switch ((Get-LocalUser).Count) {
			{($PSItem -ge 0) -and ($PSItem -le 2)}{ # 0, 1, 2
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			{($PSItem -gt 2) -and ($PSItem -le 5)}{ # 3, 4, 5
				@{
					Message = "System has 3-5 local users."
					Status = "Warning"
				}
			}
			{$PSItem -gt 5}{ # 6, ...
				@{
					Message = "System has 6 or more local users."
					Status = "False"
				}
			}
			Default {
				@{
					Message = "Cannot determine the count of local users"
					Status = "Error"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-010"
	Task = "Get the count of admin users on the system."
	Test = {	
		$status = switch ((Get-LocalGroupMember -SID "S-1-5-32-544").Count) {
			{($PSItem -ge 0) -and ($PSItem -le 2)}{ # 0, 1, 2
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			{($PSItem -gt 2) -and ($PSItem -le 5)}{ # 3, 4, 5
				@{
					Message = "System has 3-5 admin users."
					Status = "Warning"
				}
			}
			{$PSItem -gt 5}{ # 6, ...
				@{
					Message = "System has 6 or more admin users."
					Status = "False"
				}
			}
			Default {
				@{
					Message = "Cannot determine the count of admin users"
					Status = "Error"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-011"
	Task = "Ensure the status of the Bitlocker service is 'Running'."
	Test = {
		$status = switch ((Get-Service BDESVC).Status) {
			"Running"{
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			Default {
				@{
					Message = "Bitlocker service is not 'Running'."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-012"
	Task = "Ensure that Bitlocker is activated on all volumes."
	Test = {
		$volumes = (Get-Bitlockervolume).Count
		$volumes_fullenc = (Get-Bitlockervolume | Where-Object {$_.VolumeStatus -eq "FullyEncrypted"}).Count
		$enc_ratio = $volumes_fullenc / $volumes
		$status = switch ($enc_ratio) {
			{$PSItem -ge 1}{
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			{$PSItem -lt 1}{
				@{
					Message = "Bitlocker is not activated on all volumes."
					Status = "False"
				}
			}
			Default {
				@{
					Message = "Bitlocker status is unknown."
					Status = "Error"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-013"
	Task = "Ensure the status of the Windows Defender service is 'Running'."
	Test = {
		$status = switch ((Get-Service WinDefend).Status) {
			"Running"{
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			default {
				@{
					Message = "Service is not 'Running'."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-014"
	Task = "Ensure the status of the Windows Defender Advanced Threat Protection service is 'Running'."
	Test = {
		$status = switch ((Get-Service Sense).Status) {
			"Running"{
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			default {
				@{
					Message = "Service is not 'Running'."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-015"
	Task = "Ensure the status of the Windows Firewall service is 'Running'."
	Test = {
		$status = switch ((Get-Service mpssvc).Status) {
			"Running"{
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			default {
				@{
					Message = "Service is not 'Running'."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-016"
	Task = "Check if the last successful search for updates was in the past 24 hours."
	Test = {
		$tdiff = New-TimeSpan -Start (New-Object -com "Microsoft.Update.AutoUpdate").Results.LastSearchSuccessDate -End (Get-Date)
		$status = switch ($tdiff.Hours) {
			{($PSItem -ge 0) -and ($PSItem -le 24)}{
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			{($PSItem -gt 24) -and ($PSItem -le 24*5)}{
				@{
					Message = "Last search for updates was within 5 days."
					Status = "Warning"
				}
			}
			Default {
				@{
					Message = "Last search for updates was more than 5 days ago."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-017"
	Task = "Check if the last successful installation of updates was in the past 5 days." # Windows defender definitions do count as updates
	Test = {
		$tdiff = New-TimeSpan -Start (New-Object -com "Microsoft.Update.AutoUpdate").Results.LastInstallationSuccessDate -End (Get-Date)
		$status = switch ($tdiff.Hours) {
			{($PSItem -ge 0) -and ($PSItem -le 24*5)}{
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			{($PSItem -gt 24*5) -and ($PSItem -le 24*31)}{
				@{
					Message = "Last installation of updates was within the last month."
					Status = "Warning"
				}
			}
			Default {
				@{
					Message = "Last installation of updates was more than a month ago."
					Status = "False"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-018"
	Task = "Ensure Virtualization Based Security is enabled and running."
	Test = {
		$obj = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
		$status = switch ($obj) {
			{$PSItem -eq 2} {
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			{$PSItem -eq 1} {
				@{
					Message = "VBS is activated but not running."
					Status = "False"
				}
			}
			{$PSItem -eq 0} {
				@{
					Message = "VBS is not activated."
					Status = "False"
				}
			}
			default {
				@{
					Message = "Cannot get the VBS status."
					Status = "Error"
				}
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "SBD-019"
	Task = "Ensure Hypervisor-protected Code Integrity (HVCI) is running."
	Test = {
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
	Id = "SBD-020"
	Task = "Ensure Credential Guard is running."
	Test = {
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
}