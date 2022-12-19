function getKernelVersion {
	$vsplit = $(uname -r).split('-')
	if ($vsplit[1] -match '\.') { # Fedora
		$vsplit[1] = $vsplit[1].split('.')[0]
	}
	return [version]($vsplit[0] + '.' + $vsplit[1])
}
function commandExists {
	param (
		$command
	)
    return [bool](Get-Command -Name $command -ErrorAction SilentlyContinue)
}
[AuditTest] @{
	Id = "DSBD-001"
	Task = "Ensure the system is booting in UEFI mode."
	Test = {
		if (Test-Path -Path /sys/firmware/efi) {
			$status = @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			$status = @{
				Message = "System is not booting using UEFI mode."
				Status = "False"
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "DSBD-002"
	Task = "Ensure the system is using SecureBoot."
	Test = {
		if (Test-Path -Path /sys/firmware/efi) {
			if ($(mokutil --sb-state) -eq "SecureBoot enabled") {
				$status = @{
							Message = "Compliant"
							Status = "True"
				}
			} else {
				$status = @{
					Message = "System is not booting using UEFI mode."
					Status = "False"
				}
			}
		} else {
			$status = @{
				Message = "SecureBoot is only supported on UEFI."
				Status= "False"
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "DSBD-003"
	Task = "Ensure the system has a TPM Chip."
	Test = {
		if (Test-Path -Path /dev/tpm0) { # /dev/tpmrm0 is _only_ for TPM 2.0
			$status = @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			$status = @{
				Message = "Could not detect a TPM chip"
				Status = "False"
			}
		}
		return $status
	}
}
[AuditTest] @{
	Id = "DSBD-004"
	Task = "Ensure the TPM Chip is implementing specification version 2.0 or higher."
	Test = {
		if ($(getKernelVersion) -ge [version]'5.6.0.0') { # For Ubuntu 20.04 e.g.
			$spec = [float](Get-Content -Path '/sys/class/tpm/tpm0/tpm_version_major')
		} else {
		$tpm2toolsMajorVersion = [int]($(tpm2_getcap -v) | Select-String -Pattern '^.+version=\"(\d)\..+$').Matches.Groups[1].Value
			if ($tpm2toolsMajorVersion -le 3) { # old versions up to 3.x had a different syntax (Debian 9)
				$text = $(tpm2_getcap -c properties-fixed)
				$match = [regex]::matches($text, '(?smi)TPM_PT_FAMILY_INDICATOR:   as UINT32: +0[xX][0-9a-fA-F]+   as string: +\"(\d\.\d)\"').Groups[1].Value
			} else { # new versions 4.x (RHEL 8)
				$text = $(tpm2_getcap properties-fixed)
				$match = [regex]::matches($text, '(?smi)TPM2_PT_FAMILY_INDICATOR:   raw: +0[xX][0-9a-fA-F]+   value: +\"(\d\.\d)\"').Groups[1].Value
			}
			$spec = [float]$match
		}

		if ($spec -ge 2.0) {
			return @{
				Message = "Compliant"
				Status = "True"
			}
		} elseif ($spec -gt 0) {
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
	Id = "DSBD-005"
	Task = "Report the count of local users on the system."
	Test = {
		# Linux native alternative: grep -c ^ /etc/passwd
		$countUsers = (Get-Content /etc/passwd).Count
		return  @{
					Message = "System has $countUsers local users"
					Status = "None"
		}
	}
}
[AuditTest] @{
	Id = "DSBD-006"
	Task = "Report the count of local interactive users on the system."
	Test = {
		$countUsers = (Get-Content /etc/passwd | Where-Object {-not ($_ -match "/usr/sbin/nologin" -or $_ -match "/bin/false" -or $_ -match "/bin/sync")}).Count
		$status = switch ($countUsers) {
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
	Id = "DSBD-007"
	Task = "Get the count of admin users on the system."
	Test = {
		$usersSudo = ($(getent group sudo) -split ":")[3]
		$usersRoot = ($(getent group root) -split ":")[3]
		$usersWheel = ($(getent group wheel) -split ":")[3]
		$usersAdmin = ($(getent group admin) -split ":")[3]
		$usersAdm = ($(getent group adm) -split ":")[3]
		$userIdZero = ($(getent passwd 0) -split ":")[0]
		$allUsersArr = @($usersSudo, $usersRoot, $usersWheel, $usersAdmin, $usersAdm, $userIdZero) | Where-Object {$_ -ne "" -and $_ -ne $null} | Sort-Object | Get-Unique
		$status = switch ($allUsersArr.Count) {
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
	Id = "DSBD-008"
	Task = "Ensure the NX bit is set."
	Test = {
		$query = (-split (Get-Content /proc/cpuinfo | Where-Object {$_ -match '^flags.*$'} | Get-Unique)) -Contains 'nx'
		if ($query) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "The NX bit is not set."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-009"
	Task = "Ensure the ASLR is enabled."
	Test = {
		$query = [int](Get-Content /proc/sys/kernel/randomize_va_space)
		if ($query -ge 2) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} elseif ($query -eq 1) {
			return @{
				Message = "ASLR is partially enabled."
				Status = "Warning"
			}
		} else {
			return @{
				Message = "ASLR is not enabled."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-010"
	Task = "Ensure AppArmor or SELinux is enabled."
	Test = {
		if (commandExists 'aa-status') {
			$AppArmorStatus = ($(aa-status) -match '^apparmor module is loaded.*$').Count -gt 0
		}
		if (commandExists 'getenforce') {
			$SELinuxStatus = ($(getenforce) -match 'Enforcing$').Count -gt 0
		}

		if ($AppArmorStatus -or $SELinuxStatus) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "Neither AppArmor nor SELinux are enabled."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-011"
	Task = "Ensure CPU has no known vulnerabilities."
	Test = {
		$query = ((Get-Content /sys/devices/system/cpu/vulnerabilities/*) -match '^Vulnerable.*$').Count
		if ($query -eq 0) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "System has $query known CPU vulnerabilities."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-012"
	Task = "Ensure root login using SSH is not permitted."
	Test = {
		$rootLoginDisabled = [bool](Get-Content /etc/ssh/sshd_config | Select-String -Pattern '^PermitRootLogin no').Matches.Length
		if ($rootLoginDisabled) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "Login for root using SSH is permitted."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-013"
	Task = "Ensure a firewall is installed (ufw, iptables, nftables)."
	Test = {
		if (commandExists dpkg) {
			$ufwInstalled = [bool]($(dpkg -s ufw 2> /dev/zero) -match 'Status: install').Count
			$iptablesInstalled = [bool]($(dpkg -s iptables 2> /dev/zero) -match 'Status: install').Count
			$nftablesInstalled = [bool]($(dpkg -s nftables 2> /dev/zero) -match 'Status: install').Count
		}
		if (commandExists rpm) {
			$ufwInstalled = [bool]($(rpm -qa) -match '^ufw.+$').Count
			$iptablesInstalled = [bool]($(rpm -qa) -match '^iptables.+$').Count
			$nftablesInstalled = [bool]($(rpm -qa) -match '^nftables.+$').Count
		}
		if ($ufwInstalled -or $iptablesInstalled -or $nftablesInstalled) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "Login for root using SSH is permitted."
				Status = "False"
			}
		}
	}
}
function getFilePermissionsRegex {
	Param(
		[Parameter(Mandatory=$true)][String][ValidateNotNullOrEmpty()]$filePath
	)
	$text = stat $filePath
	$match = [regex]::matches($text, '\S+:\s+\((\d+)\/\S+\)\s+Uid:\s+\(\s*(\d+)\/\s+(\S+)\)\s+Gid:\s+\(\s+(\d+)\/\s+(\S+)\)')
	return [ordered]@{
		permissionsOct = $match.Groups[1].Value
		ownerUserId = $match.Groups[2].Value
		ownerUserName = $match.Groups[3].Value
		ownerGroupId = $match.Groups[4].Value
		ownerGroupName = $match.Groups[5].Value
	}
}
function checkFilePermissions {
	Param(
		[Parameter(Mandatory=$true)][String][ValidateNotNullOrEmpty()]$filePath,
		[Parameter(Mandatory=$true)][String][ValidateNotNullOrEmpty()]$permissionsOct,
		[Parameter(Mandatory=$true)][String][ValidateNotNullOrEmpty()]$ownerUserName,
		[Parameter(Mandatory=$true)][String][ValidateNotNullOrEmpty()]$ownerGroupName
	)
	# calculate mode
	$item = Get-Item $filePath
	$modeLowerBits = $item.UnixStat.Mode -band 4095 # 4095_(10) = 111111111111_(2) = 7777_(8) = FFF_(16)
	$mode = [Convert]::ToString($modeLowerBits, 8) # Conversion not necessary in future: https://github.com/PowerShell/PowerShell/issues/16757 , alternative: stat -c '%a' /etc/passwd
	# check for same or more restricted permissions
	foreach ($i in 0..($mode.Length - 1)) {
		if ($mode[$i] -gt $permissionsOct[$i]) {
			return $false # = less restrictive
		}
	}
	# check owning user and group
	return $item.User -eq $ownerUserName -and $item.Group -eq $ownerGroupName
}
[AuditTest] @{
	Id = "DSBD-014"
	Task = "Ensure /etc/passwd and /etc/passwd- have proper file permissions."
	Test = {
		$result = checkFilePermissions '/etc/passwd' '644' 'root' 'root'
		if (Test-Path -Path '/etc/passwd-' -PathType Leaf) {
			$result = $result -and (checkFilePermissions '/etc/passwd-' '644' 'root' 'root')
		}
		if ($result) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "The file permissions are not set correctly."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-015"
	Task = "Ensure /etc/shadow and /etc/shadow- have proper file permissions."
	Test = {
		$result = (checkFilePermissions '/etc/shadow' '640' 'root' 'root') -or (checkFilePermissions '/etc/shadow' '640' 'root' 'shadow')
		if (Test-Path -Path '/etc/shadow-' -PathType Leaf) {
			$resultDash = (checkFilePermissions '/etc/shadow-' '640' 'root' 'root') -or (checkFilePermissions '/etc/shadow-' '640' 'root' 'shadow')
			$result = $result -and $resultDash
		}
		if ($result) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "The file permissions are not set correctly."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-016"
	Task = "Ensure /etc/group and /etc/group- have proper file permissions."
	Test = {
		$result = checkFilePermissions '/etc/group' '644' 'root' 'root'
		if (Test-Path -Path '/etc/group-' -PathType Leaf) {
			$result = $result -and (checkFilePermissions '/etc/group-' '644' 'root' 'root')
		}
		if ($result) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "The file permissions are not set correctly."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-017"
	Task = "Ensure /etc/gshadow and /etc/gshadow- have proper file permissions."
	Test = {
		$result = (checkFilePermissions '/etc/gshadow' '640' 'root' 'root') -or (checkFilePermissions '/etc/gshadow' '640' 'root' 'shadow')
		if (Test-Path -Path '/etc/gshadow-' -PathType Leaf) {
			$resultDash = (checkFilePermissions '/etc/gshadow-' '640' 'root' 'root') -or (checkFilePermissions '/etc/gshadow-' '640' 'root' 'shadow')
			$result = $result -and $resultDash
		}
		if ($result) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "The file permissions are not set correctly."
				Status = "False"
			}
		}
	}
}
[AuditTest] @{
	Id = "DSBD-018"
	Task = "Ensure /etc/ssh/sshd_config has proper file permissions."
	Test = {
		$result = checkFilePermissions '/etc/ssh/sshd_config' '600' 'root' 'root'
		if ($result) {
			return @{
						Message = "Compliant"
						Status = "True"
			}
		} else {
			return @{
				Message = "The file permissions are not set correctly."
				Status = "False"
			}
		}
	}
}