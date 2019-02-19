@{
	RegistrySettings = @(

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
	AuditPolicies = @(
		@{
			Id = "CIS 17.1.1"
			Subcategory = "Credential Validation"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.1"
			Subcategory = "Application Group Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.2"
			Subcategory = "Computer Account Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.4"
			Subcategory = "Other Account Management Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.5"
			Subcategory = "Security Group Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.2.5"
			Subcategory = "User Account Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.3.1"
			Subcategory = "Plug and Play Events"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.3.2"
			Subcategory = "Process Creation"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.5.1"
			Subcategory = "Account Lockout"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.5.2"
			Subcategory = "Group Membership"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.5.3"
			Subcategory = "Logoff"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.5.4"
			Subcategory = "Logon"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.5.5"
			Subcategory = "Other Logon/Logoff Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.5.6"
			Subcategory = "Special Logon"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.6.1"
			Subcategory = "Removable Storage"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.7.1"
			Subcategory = "Audit Policy Change"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.7.2"
			Subcategory = "Authentication Policy Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.7.3"
			Subcategory = "Authorization Policy Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.8.1"
			Subcategory = "Sensitive Privilege Use"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.9.1"
			Subcategory = "IPsec Driver"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.9.2"
			Subcategory = "Other System Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.9.3"
			Subcategory = "Security State Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "CIS 17.9.4"
			Subcategory = "Security System Extension"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "CIS 17.9.5"
			Subcategory = "System Integrity"
			AuditFlag = 'Success and Failure'
		}
	)
}