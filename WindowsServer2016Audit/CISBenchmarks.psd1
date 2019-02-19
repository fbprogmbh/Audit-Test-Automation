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
}