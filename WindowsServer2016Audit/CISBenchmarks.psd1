@{
	RegistrySettings = @(
		# Account Policies
		@{
			Id = "2.3.1.2"
			Task = "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name = "NoConnectedUser"
			Value = 0 #?
		}
		@{
			Id = "2.3.2.2"
			Task = "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
			Name = "CrashOnAuditFail"
			Value = 0 #?
		}
		@{
			Id = "2.3.4.1"
			Task = "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"

			Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
			Name = "AllocateDASD"
			Value = 0 #?
		}
		@{
			Id = "2.3.4.2"
			Task = "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
			Name = "AddPrinterDrivers"
			Value = 1 #?
		}
		@{
			Id = "2.3.5.1"
			Task = "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)"
			Role = "PrimaryDomainController"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
			Name = "SubmitControl"
			Value = 0 #?
		}
		@{
			Id = "2.3.7.1"
			Task = "Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'"
			Role = "PrimaryDomainController"

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name = "DontDisplayLastUserName"
			Value = 1 #?
		}
		@{
			Id = "2.3.7.2"
			Task = "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
			Role = "PrimaryDomainController"

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name = "DisableCAD"
			Value = 1 #?
		}
		@{
			Id = "2.3.9.4"
			Task = "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name = "enableforcedlogoff"
			Value = 1 #?
		}
		@{
			Id = "2.3.9.5"
			Task = "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)"
			Role = "MemberServer"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name = "SMBServerNameHardeningLevel"
			Value = 0 #?
		}
		@{
			Id = "2.3.10.6"
			Task = "Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only)"
			Role = "PrimaryDomainController"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name = "NullSessionPipes"
			Value = "LSARPC, NETLOGON, SAMR" #?
		}
		@{
			Id = "2.3.10.7"
			Task = "Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only)"
			Role = "MemberServer"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters: "
			Name = "NullSessionPipes"
			Value = "" #?
		}
		@{
			Id = "2.3.10.8"
			Task = "Configure 'Network access: Remotely accessible registry paths'"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
			Name = "Machine"
			Value = "System\CurrentControlSet\Control\ProductOptions;System\CurrentControlSet\Control\Server;Applications Software\Microsoft\Windows NT\CurrentVersion" #?
		}
		# @{
		# 	Id = "2.3.10.11"
		# 	Task = "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)"
		# 	Role = "MemberServer"

		# 	Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
		# 	Name = "restrictremotesam"
		# 	Value = "Administrators: Remote Access: Allow" #?
		# }
		@{
			Id = "2.3.10.12"
			Task = "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name = "NullSessionShares"
			Value = "" #?
		}
		@{
			Id = "2.3.10.13"
			Task = "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
			Name = "ForceGuest"
			Value = "Classic - local users authenticate as themselves." #?
		}
		@{
			Id = "2.3.13.1"
			Task = "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name = "ShutdownWithoutLogon"
			Value = 0 #?
		}
		@{
			Id = "2.3.17.8"
			Task = "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name = "PromptOnSecureDesktop"
			Value = 1 #?
		}

		# Control Panel
		@{
			Id = "18.1.1.1"
			Task = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled"

			Path = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
			Name = "NoLockScreenCamera"
			Value = 1
		}
		@{
			Id = "18.1.2.2"
			Task = "Ensure 'Allow input personalization' is set to 'Disabled' "

			Path = "HKLM:\Software\Policies\Microsoft\InputPersonalization"
			Name = "AllowInputPersonalization"
			Value = 0
		}
		@{
			Id = "18.1.3"
			Task = "Ensure 'Allow Online Tips' is set to 'Disabled'"

			Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
			Name = "AllowOnlineTips"
			Value = 0
		}

		# LAPS
		@{
			Id = "18.2.1"
			Title = "Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)"
			Task = "MemberServer"

			Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D087DE603E3EA}"
			Name = "DllName"
			Value = 1 #TODO: Need real value
		}
		@{
			Id = "18.2.2"
			Title = "Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'"
			Task = "MemberServer"

			Path = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name = "PwdExpirationProtectionEnabled"
			Value = 1 #TODO: Need real value
		}
		@{
			Id = "18.2.3"
			Task = "Ensure 'Enable Local Admin Password Management' is set to 'Enabled'"
			Role = "MemberServer"

			Path = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name = "AdmPwdEnabled"
			Value = 1 #TODO: Need real value
		}
		@{
			Id = "18.2.4"
			Task = "Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' "
			Role = "MemberServer"

			Path = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name = "PasswordComplexity"
			Value = 1 #TODO: Need real value
		}
		@{
			Id = "18.2.5"
			Task = "Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'"
			Role = "MemberServer"

			Path = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name = "PasswordLength"
			Value = 1 #TODO: Need real value
		}
		@{
			Id = "18.2.6"
			Task = "Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'"
			Role = "MemberServer"

			Path = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name = "PasswordAgeDays"
			Value = 1 #TODO: Need real value
		}
	)
	UserRights = @(
		@{
			Id = "2.2.6"
			Task = "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"

			Policy = "SeIncreaseQuotaPrivilege"
			Identity = "Administrators", "Local Service", "Network Service"
		}
		@{
			Id = "2.2.9"
			Task = "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)"
			Role = "MemberServer"

			Policy = "SeRemoteInteractiveLogonRight"
			Identity = "Administrators", "Remote Desktop Users"
		}
		@{
			Id = "2.2.11"
			Task = "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"

			Policy = "SeSystemtimePrivilege"
			Identity = "Administrators", "Local Service"
		}
		@{
			Id = "2.2.12"
			Task = "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"

			Policy = "SeTimeZonePrivilege"
			Identity = "Administrators", "Local Service"
		}
		# ???
		# @{
		# 	Id = "2.2.18"
		# 	Task = "Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)"

		# 	Policy = "Create_symbolic_links"
		# 	Identity = "Administrators"
		# }
		# ???
		# @{
		# 	Id = "2.2.32"
		# 	Task = "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only)"

		# 	Policy = "Create_symbolic_links"
		# 	Identity = "Administrators"
		# }
		@{
			Id = "2.2.39"
			Task = "Ensure 'Modify an object label' is set to 'No One'"

			Policy = "SeRelabelPrivilege"
			Identity = @()
		}
		@{
			Id = "2.2.43"
			Task = "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"

			Policy = "SeSystemProfilePrivilege"
			Identity = "Administrators", "NT SERVICE\WdiServiceHost"
		}
		@{
			Id = "2.2.44"
			Task = "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"

			Policy = "SeAssignPrimaryTokenPrivilege"
			Identity = "Local Service", "Network Service"
		}
		@{
			Id = "2.2.46"
			Task = "Ensure 'Shut down the system' is set to 'Administrators'"

			Policy = "SeShutdownPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "2.2.47"
			Task = "Ensure 'Synchronize directory service data' is set to 'No One' (DC only)"
			Role = "PrimaryDomainController"

			Policy = "SeSyncAgentPrivilege"
			Identity = @()
		}
	)
	AccountPolicies = @(
		@{
			Id = "2.3.1.1"
			Task = "Ensure 'Accounts: Administrator account status' is set to 'Disabled' (MS only)"
			Role = "MemberServer"

			Policy = "EnableAdminAccount"
			Value = "0"
		}
		# 2.3.1.2

	)
	AuditPolicies = @(
		@{
			Id = "CIS 17.1.1"
			Task = "Credential Validation is set to Success and Failure"

			Subcategory = "Credential Validation"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.1"
			Task = "Application Group Management is set to Success and Failure"

			Subcategory = "Application Group Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.2"
			Task = "Computer Account Management is set to Success and Failure"

			Subcategory = "Computer Account Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.4"
			Task = "Other Account Management Events is set to Success and Failure"

			Subcategory = "Other Account Management Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.5"
			Task = "Security Group Management is set to Success and Failure"

			Subcategory = "Security Group Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.5"
			Task = "User Account Management is set to Success and Failure"

			Subcategory = "User Account Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.3.1"
			Task = "Plug and Play Events is set to Success"

			Subcategory = "Plug and Play Events"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.3.2"
			Task = "Process Creation is set to Success"

			Subcategory = "Process Creation"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.5.1"
			Task = "Account Lockout is set to Success and Failure"

			Subcategory = "Account Lockout"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.5.2"
			Task = "Group Membership is set to Success"

			Subcategory = "Group Membership"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.5.3"
			Task = "Logoff is set to Success"

			Subcategory = "Logoff"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.5.4"
			Task = "Logon is set to Success and Failure"

			Subcategory = "Logon"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.5.5"
			Task = "Other Logon/Logoff Events is set to Success and Failure"

			Subcategory = "Other Logon/Logoff Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.5.6"
			Task = "Special Logon is set to Success"

			Subcategory = "Special Logon"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.6.1"
			Task = "Removable Storage is set to Success and Failure"

			Subcategory = "Removable Storage"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.7.1"
			Task = "Audit Policy Change is set to Success and Failure"

			Subcategory = "Audit Policy Change"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.7.2"
			Task = "Authentication Policy Change is set to Success"

			Subcategory = "Authentication Policy Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.7.3"
			Task = "Authorization Policy Change is set to Success"

			Subcategory = "Authorization Policy Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.8.1"
			Task = "Sensitive Privilege Use is set to Success and Failure"

			Subcategory = "Sensitive Privilege Use"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.9.1"
			Task = "IPsec Driver is set to Success and Failure"

			Subcategory = "IPsec Driver"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.9.2"
			Task = "Other System Events is set to Success and Failure"

			Subcategory = "Other System Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.9.3"
			Task = "Security State Change is set to Success"

			Subcategory = "Security State Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.9.4"
			Task = "Security System Extension is set to Success and Failure"

			Subcategory = "Security System Extension"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.9.5"
			Task = "System Integrity is set to Success and Failure"

			Subcategory = "System Integrity"
			AuditFlag = 'Success and Failure'
		}
	)
	FirewallProfileSettings = @(
		@{
			Id = "9.1.1"
			Task = "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"

			Profile = "Domain"
			Setting = "Enabled"
			Value = "True"
		}
		@{
			Id = "9.1.2"
			Task = "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"

			Profile = "Domain"
			Setting = "DefaultInboundAction"
			Value = "False"
		}
		@{
			Id = "9.1.3"
			Task = "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"

			Profile = "Domain"
			Setting = "DefaultOutboundAction"
			Value = "True"
		}
		@{
			Id = "9.1.4"
			Task = "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"

			Profile = "Domain"
			Setting = "NotifyOnListen"
			Value = "False"
		}
		@{
			Id = "9.1.5"
			Task = "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'"

			Profile = "Domain"
			Setting = "LogFileName"
			Value = "%systemroot%\system32\LogFiles\Firewall\domainfw.log"
		}
		@{
			Id = "9.1.6"
			Task = "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"

			Profile = "Domain"
			Setting = "LogMaxSizeKilobytes"
			Value = "16384 KB or greater"
			ValueType = "ValueRange"
		}
		@{
			Id = "9.1.7"
			Task = "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"

			Profile = "Domain"
			Setting = "LogBlocked"
			Value = "True"
		}
		@{
			Id = "9.1.8"
			Task = "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"

			Profile = "Domain"
			Setting = "LogAllowed"
			Value = "True"
		}


		@{
			Id = "9.2.1"
			Task = "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"

			Profile = "Private"
			Setting = "Enabled"
			Value = "True"
		}
		@{
			Id = "9.2.2"
			Task = "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"

			Profile = "Private"
			Setting = "DefaultInboundAction"
			Value = "False"
		}
		@{
			Id = "9.2.3"
			Task = "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"

			Profile = "Private"
			Setting = "DefaultOutboundAction"
			Value = "True"
		}
		@{
			Id = "9.2.4"
			Task = "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"

			Profile = "Private"
			Setting = "NotifyOnListen"
			Value = "False"
		}
		@{
			Id = "9.2.5"
			Task = "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'"

			Profile = "Private"
			Setting = "LogFileName"
			Value = "%systemroot%\system32\LogFiles\Firewall\privatefw.log"
		}
		@{
			Id = "9.2.6"
			Task = "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"

			Profile = "Private"
			Setting = "LogMaxSizeKilobytes"
			Value = "16384 KB or greater"
			ValueType = "ValueRange"
		}
		@{
			Id = "9.2.7"
			Task = "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"

			Profile = "Private"
			Setting = "LogBlocked"
			Value = "True"
		}
		@{
			Id = "9.2.8"
			Task = "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"

			Profile = "Private"
			Setting = "LogAllowed"
			Value = "True"
		}


		@{
			Id = "9.3.1"
			Task = "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"

			Profile = "Public"
			Setting = "Enabled"
			Value = "True"
		}
		@{
			Id = "9.3.2"
			Task = "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"

			Profile = "Public"
			Setting = "DefaultInboundAction"
			Value = "False"
		}
		@{
			Id = "9.3.3"
			Task = "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"

			Profile = "Public"
			Setting = "DefaultOutboundAction"
			Value = "True"
		}
		@{
			Id = "9.3.4"
			Task = "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"

			Profile = "Public"
			Setting = "NotifyOnListen"
			Value = "False"
		}
		# Run Get-NetFirewallProfile -Name Public -PolicyStore localhost
		@{ # Problems
			Id = "9.3.5"
			Task = "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"

			Profile = "Public"
			Setting = "AllowLocalFirewallRules"
			Value = "False"
		}
		@{ # Problems
			Id = "9.3.6"
			Task = "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"

			Profile = "Public"
			Setting = "AllowLocalIPsecRules"
			Value = "False"
		}
		@{
			Id = "9.3.7"
			Task = "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'"

			Profile = "Public"
			Setting = "LogFileName"
			Value = "%systemroot%\system32\LogFiles\Firewall\publicfw.log"
		}
		@{
			Id = "9.3.8"
			Task = "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"

			Profile = "Public"
			Setting = "LogMaxSizeKilobytes"
			Value = "16384 KB or greater"
			ValueType = "ValueRange"
		}
		@{
			Id = "9.3.9"
			Task = "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"

			Profile = "Public"
			Setting = "LogBlocked"
			Value = "True"
		}
		@{
			Id = "9.3.10"
			Task = "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"

			Profile = "Public"
			Setting = "LogAllowed"
			Value = "True"
		}
	)
}