$RootPath = Split-Path $MyInvocation.MyCommand.Path -Parent
$RootPath = Split-Path $RootPath -Parent
. "$RootPath\Helpers\AuditGroupFunctions.ps1"
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
[AuditTest] @{
	Id = "SBD-009"
	Task = "Get amount of active local users on system."
	Test = {	
		$users = Get-LocalUser;
		$amountOfActiveUser = 0;
		foreach($user in $users){
			if($user.Enabled -eq $True){
				$amountOfActiveUser ++;
			}
		}
		$status = switch ((Get-LocalUser).Count) {
			{($amountOfActiveUser -ge 0) -and ($amountOfActiveUser -le 2)}{ # 0, 1, 2
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			{($amountOfActiveUser -gt 2) -and ($amountOfActiveUser -le 5)}{ # 3, 4, 5
				@{
					Message = "System has $($amountOfActiveUser) local users."
					Status = "Warning"
				}
			}
			{$amountOfActiveUser -gt 5}{ # 6, ...
				@{
					Message = "System has 6 or more local users. (Currently $($amountOfActiveUser) users.)"
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
	Task = "Get amount of users and groups in administrators group on system."
	Test = {	
		try { 
			try{
				$userAndGroups = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop
				foreach($user in $userAndGroups){
					if($user.PrincipalSource -eq "Local"){
						$amountOfUserAndGroups ++;
					}
				}
				$status = switch ($amountOfUserAndGroups.Count) {
					{($amountOfUserAndGroups -ge 0) -and ($amountOfUserAndGroups -le 2)}{ # 0, 1, 2
						@{
							Message = "Amount of entries: $amountOfUserAndGroups; `r`n $group_members"
							Status = "True"
						}
					}
					{($amountOfUserAndGroups -gt 2) -and ($amountOfUserAndGroups -le 5)}{ # 3, 4, 5
						@{
							Message = "Amount of entries: $amountOfUserAndGroups; `r`n $group_members"
							Status = "Warning"
						}
					}
					{$amountOfUserAndGroups -gt 5}{ # 6, ...
						@{
							Message = "Amount of entries: $amountOfUserAndGroups; `r`n $group_members"
							Status = "False"
						}
					}
					Default {
						@{
							Message = "Cannot determine the count of admin users. Please check manually."
							Status = "Error"
						}
					}
				}
				return $status
			}
			catch{
				$roleValue = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole
				if($roleValue -eq 4 -or $roleValue -eq 5){
					return @{
						Message = "Not applicable. This audit only applies to Domain controllers."
						Status = "None"
					}
				}
				#List all groups 
				$group = Get-LocalGroup -sid "S-1-5-32-544"
				$group = [ADSI]"WinNT://$env:COMPUTERNAME/$group"
				$group_members = @($group.Invoke('Members') | % {([adsi]$_).path})
				$amountOfUserAndGroups = 0;
				$amountOfUserAndGroups = $group_members.Count;
			}
			$status = switch ($amountOfUserAndGroups.Count) {
				{($amountOfUserAndGroups -ge 0) -and ($amountOfUserAndGroups -le 2)}{ # 0, 1, 2
					@{
						Message = "Amount of entries: $amountOfUserAndGroups; `r`n $group_members `r`n *Some SIDs could not be resolved. Please check manually."
						Status = "True"
					}
				}
				{($amountOfUserAndGroups -gt 2) -and ($amountOfUserAndGroups -le 5)}{ # 3, 4, 5
					@{
						Message = "Amount of entries: $amountOfUserAndGroups; `r`n $group_members `r`n *Some SIDs could not be resolved. Please check manually."
						Status = "Warning"
					}
				}
				{$amountOfUserAndGroups -gt 5}{ # 6, ...
					@{
						Message = "Amount of entries: $amountOfUserAndGroups; `r`n $group_members `r`n *Some SIDs could not be resolved. Please check manually."
						Status = "False"
					}
				}
				Default {
					@{
						Message = "Cannot determine the count of admin users. Please check manually."
						Status = "Error"
					}
				}
			}
		} catch {
			$theError = $_
			if ($theError.Exception -like "*1789*") {
				@{
			 		Message = "Not all users could be enumerated, please manually check members of administrators group"
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
		if (isWindows8OrNewer) {
			if ((Get-WindowsOptionalFeature -Online -FeatureName Bitlocker).State -eq 'Disabled') {
				return @{
					Message = "Bitlocker feature is not installed."
					Status = "False"
				}
			}
		}
		$status = switch ((Get-Service BDESVC -ErrorAction SilentlyContinue).Status) {
			"Running" {
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
		try {
			if (isWindows8OrNewer) {
				if ((Get-WindowsOptionalFeature -Online -FeatureName Bitlocker).State -eq 'Disabled') {
					return @{
						Message = "Bitlocker feature is not installed."
						Status = "False"
					}
				}
				$volumes = (Get-Bitlockervolume -ErrorAction Stop).Count
				$volumes_fullenc = (Get-Bitlockervolume | Where-Object {$_.VolumeStatus -eq "FullyEncrypted"}).Count
			} else {
				$volumes = (Get-CimInstance -Class Win32_EncryptableVolume -namespace Root\CIMV2\Security\MicrosoftVolumeEncryption | Measure-Object).Count
				$volumes_fullenc = (Get-CimInstance -Class Win32_EncryptableVolume -namespace Root\CIMV2\Security\MicrosoftVolumeEncryption | Where-Object {$_.ProtectionStatus -eq 1} | Measure-Object).Count
			}
		} catch [System.Runtime.InteropServices.COMException] {
			return @{
				Message = "Bitlocker status is unknown."
				Status = "Error"
			}
		}
		if ($volumes -lt 1) {
			return @{
				Message = "Bitlocker status is unknown."
				Status = "Error"
			}
		}
		$enc_ratio = $volumes_fullenc / $volumes
		$status = switch ($enc_ratio) {
			{$enc_ratio -ge 1}{
				@{
					Message = "Compliant"
					Status = "True"
				}
			}
			{$enc_ratio -lt 1}{
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
		try{
			$status = switch ((Get-Service WinDefend -ErrorAction Stop).Status) {
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
		catch [Microsoft.PowerShell.Commands.ServiceCommandException]{
			return @{
				Message = "Current version is not supported."
				Status = "None"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-014"
	Task = "Ensure Windows Defender Application Guard is enabled."
	Test = {
		if (isWindows10OrNewer) {
			$state = (Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).State
			if ($state -eq 'Enabled') {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			else {
				return @{
					Message = "Windows Defender Application Guard is not enabled."
					Status = "False"
				}
			}
		}
		else {
			return @{
				Message = "System does not support this feature (Windows 10 or newer required)."
				Status = "None"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-015"
	Task = "Ensure the Windows Firewall is enabled on all profiles."
	Test = {
		if (isWindows8OrNewer) {
			if ((Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'False'} | Measure-Object).Count -gt 0) {
				return @{
					Message = "Firewall is not enabled on all profiles"
					Status = "False"
				}
			}
			else {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
		}
		else {
			$fw = New-Object -ComObject hnetcfg.fwpolicy2 
			$domain = $fw.FireWallEnabled(1)
			$private = $fw.FireWallEnabled(2)
			$public = $fw.FireWallEnabled(4)
			if ($domain -and $private -and $public) {
				return @{
					Message = "Compliant"
					Status = "True"
				}
			}
			else {
				return @{
					Message = "Firewall is not enabled on all profiles"
					Status = "False"
				}
			}
		}
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
		if (isWindows10OrNewer) {
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
		else {
			return @{
				Message = "System does not support this feature (Windows 10 or newer required)."
				Status = "None"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-019"
	Task = "Ensure Hypervisor-protected Code Integrity (HVCI) is running."
	Test = {
		if (isWindows10OrNewer) {
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
		else {
			return @{
				Message = "System does not support this feature (Windows 10 or newer required)."
				Status = "None"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-020"
	Task = "Ensure Credential Guard is running."
	Test = {
		if (isWindows10OrNewer) {
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
		else {
			return @{
				Message = "System does not support this feature (Windows 10 or newer required)."
				Status = "None"
			}
		}
	}
}
[AuditTest] @{
	Id = "SBD-021"
	Task = "Ensure Attack Surface Reduction (ASR) rules are enabled."
	Test = {
		if (isWindows10OrNewer) {
			$ruleids = (Get-MpPreference).AttackSurfaceReductionRules_Ids
			$ruleactions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
			$RuleTable = for ($i = 0; $i -lt $ruleids.Count; $i++) {
				[PSCustomObject]@{
					RuleId = $ruleids[$i]
					RuleAction = $ruleactions[$i]
				}
			}
			$countEnabled = ($RuleTable | Where-Object {$_.RuleAction -eq 1} | Measure-Object).Count
			
			$status = switch ($countEnabled) {
				{$PSItem -ge 12}{
					@{
						Message = "Compliant ($($countEnabled) rules enabled). For more information on ASR rules, check corresponding benchmarks."
						Status = "True"
					}
				}
				{($PSItem -ge 1) -and ($PSItem -lt 12)}{
					@{
						Message = "$($countEnabled) ASR rules are activated. For more information on ASR rules, check corresponding benchmarks."
						Status = "Warning"
					}
				}
				Default {
					@{
						Message = "ASR rules are not enabled."
						Status = "False"
					}
				}
			}
			return $status
		}
		else {
			$windefrunning = CheckWindefRunning
			if ((-not $windefrunning)) {
				return @{
					Message = "This rule requires Windows Defender Antivirus to be enabled."
					Status = "None"
				}
			}                           
			$countEnabled = 0
			$Rule1 = @{
				Path1 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
				Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
				Value = "ExploitGuard_ASR_Rules"
			};
			$bool = $($Rule1.Path1), $($Rule1.Path2) | Test-MultiplePaths -Key $($Rule1.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}
			$Rule2 = @{
				Path1 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Path2 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Value = "26190899-1602-49e8-8b27-eb1d0a1ce869"
			};
			$bool = $($Rule2.Path1), $($Rule2.Path2) | Test-MultiplePaths -Key $($Rule2.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}
			$Rule3 = @{
				Path1 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Path2 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Value = "3b576869-a4ec-4529-8536-b80a7769e899"
			};
			$bool = $($Rule3.Path1), $($Rule3.Path2) | Test-MultiplePaths -Key $($Rule3.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}
			$Rule4 = @{
				Path1 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Path2 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Value = "5beb7efe-fd9a-4556-801d-275e5ffc04cc" 
			};
			$bool = $($Rule4.Path1), $($Rule4.Path2) | Test-MultiplePaths -Key $($Rule4.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}
			$Rule5 = @{
				Path1 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Path2 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Value = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
			};
			$bool = $($Rule5.Path1), $($Rule5.Path2) | Test-MultiplePaths -Key $($Rule5.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}
			$Rule6 = @{
				Path1 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Path2 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Value = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
			};
			$bool = $($Rule6.Path1), $($Rule6.Path2) | Test-MultiplePaths -Key $($Rule6.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}
			$Rule7 = @{
				Path1 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Path2 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Value = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
			};
			$bool = $($Rule7.Path1), $($Rule7.Path2) | Test-MultiplePaths -Key $($Rule7.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}
			$Rule8 = @{
				Path1 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Path2 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Value = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
			};
			$bool = $($Rule8.Path1), $($Rule8.Path2) | Test-MultiplePaths -Key $($Rule8.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}
			$Rule9 = @{
				Path1 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Path2 ="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
				Value = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
			};
			$bool = $($Rule9.Path1), $($Rule9.Path2) | Test-MultiplePaths -Key $($Rule9.Value) -ExpectedValue 1 
			if ($bool.Status -eq "True") {
				$countEnabled++;
			}

			$status = switch ($countEnabled) {
				{$PSItem -ge 9}{
					@{
						Message = "Compliant ($($countEnabled) rules enabled). For more information on ASR rules, check corresponding benchmarks."
						Status = "True"
					}
				}
				{($PSItem -ge 1) -and ($PSItem -lt 9)}{
					@{
						Message = "$($countEnabled) ASR rules are activated. For more information on ASR rules, check corresponding benchmarks."
						Status = "Warning"
					}
				}
				Default {
					@{
						Message = "ASR rules are not enabled."
						Status = "False"
					}
				}
			}

			return $status
		}
	}
}