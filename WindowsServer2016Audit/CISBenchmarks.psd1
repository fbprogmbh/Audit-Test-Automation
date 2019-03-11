@{
	# registry values need to be checked
	RegistrySettings = @(
		# Account Policies
		@{
			Id    = "2.3.1.2"
			Task  = "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"

			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name  = "NoConnectedUser"
			Value = 3
		}
		@{
			Id    = "2.3.2.2"
			Task  = "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
			Name  = "CrashOnAuditFail"
			Value = 0
		}
		@{
			Id    = "2.3.4.1"
			Task  = "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"

			Path  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
			Name  = "AllocateDASD"
			Value = 0
		}
		@{
			Id    = "2.3.4.2"
			Task  = "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
			Name  = "AddPrinterDrivers"
			Value = 1
		}
		@{
			Id    = "2.3.5.1"
			Task  = "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)"
			Role = "PrimaryDomainController"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
			Name  = "SubmitControl"
			Value = 0
		}
		@{
			Id    = "2.3.7.1"
			Task  = "Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'"

			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name  = "DontDisplayLastUserName"
			Value = 1
		}
		@{
			Id    = "2.3.7.2"
			Task  = "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"

			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name  = "DisableCAD"
			Value = 0
		}
		@{
			Id    = "2.3.9.4"
			Task  = "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name  = "enableforcedlogoff"
			Value = 1
		}
		@{
			Id    = "2.3.9.5"
			Task  = "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)"
			Role = "MemberServer", "StandaloneServer"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name  = "SMBServerNameHardeningLevel"
			Value = 1
		}
		@{
			Id    = "2.3.10.6"
			Task  = "Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only)"
			Role = "PrimaryDomainController"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name  = "NullSessionPipes"
			Value = "LSARPC", "NETLOGON", "SAMR"
		}
		@{
			Id    = "2.3.10.7"
			Task  = "Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only)"
			Role = "MemberServer", "StandaloneServer"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name  = "NullSessionPipes"
			Value = @("")
			ValueType  = "MultiString"
		}
		@{
			Id    = "2.3.10.8"
			Task  = "Configure 'Network access: Remotely accessible registry paths'"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
			Name  = "Machine"
			Value = @(
				"System\CurrentControlSet\Control\ProductOptions",
				"System\CurrentControlSet\Control\Server Applications", 
				"Software\Microsoft\Windows NT\CurrentVersion"
			)
		}
		@{
			Id    = "2.3.10.9"
			Task  = "Configure 'Network access: Remotely accessible registry paths and sub-paths'"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
			Name  = "Machine"
			Value = @(
				"System\CurrentControlSet\Control\Print\Printers", 
				"System\CurrentControlSet\Services\Eventlog", 
				"Software\Microsoft\OLAP Server", 
				"Software\Microsoft\Windows NT\CurrentVersion\Print", 
				"Software\Microsoft\Windows NT\CurrentVersion\Windows", 
				"System\CurrentControlSet\Control\ContentIndex", 
				"System\CurrentControlSet\Control\Terminal Server", 
				"System\CurrentControlSet\Control\Terminal Server\UserConfig", 
				"System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration", 
				"Software\Microsoft\Windows NT\CurrentVersion\Perflib", 
				"System\CurrentControlSet\Services\SysmonLog"
			)
		}
		@{
			Id    = "2.3.10.12"
			Task  = "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
			Name  = "NullSessionShares"
			Value = @("")
			ValueType  = "MultiString"
		}
		@{
			Id    = "2.3.10.13"
			Task  = "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"

			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
			Name  = "ForceGuest"
			Value = 0
		}
		@{
			Id    = "2.3.13.1"
			Task  = "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"

			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name  = "ShutdownWithoutLogon"
			Value = 0
		}
		@{
			Id    = "2.3.17.8"
			Task  = "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"

			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name  = "PromptOnSecureDesktop"
			Value = 1
		}

		# Control Panel
		@{
			Id    = "18.1.1.1"
			Task  = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled"

			Path  = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
			Name  = "NoLockScreenCamera"
			Value = 1
		}
		@{
			Id    = "18.1.2.2"
			Task  = "Ensure 'Allow input personalization' is set to 'Disabled' "

			Path  = "HKLM:\Software\Policies\Microsoft\InputPersonalization"
			Name  = "AllowInputPersonalization"
			Value = 0
		}
		@{
			Id    = "18.1.3"
			Task  = "Ensure 'Allow Online Tips' is set to 'Disabled'"

			Path  = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
			Name  = "AllowOnlineTips"
			Value = 0
		}

		# LAPS
		# @{
		# 	Id    = "18.2.1"
		# 	Task  = "Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)"
		# 	Role = "MemberServer"

		# 	Path  = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D087DE603E3EA}"
		# 	Name  = "DllName"
		# 	Value = 1 #TODO: Need real value
		# }
		@{
			Id    = "18.2.2"
			Task  = "Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'"
			Role = "MemberServer"

			Path  = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name  = "PwdExpirationProtectionEnabled"
			Value = 1
		}
		@{
			Id    = "18.2.3"
			Task  = "Ensure 'Enable Local Admin Password Management' is set to 'Enabled'"
			Role = "MemberServer"

			Path  = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name  = "AdmPwdEnabled"
			Value = 1
		}
		@{
			Id    = "18.2.4"
			Task  = "Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' "
			Role = "MemberServer"

			Path  = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name  = "PasswordComplexity"
			Value = 4
		}
		@{
			Id    = "18.2.5"
			Task  = "Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'"
			Role = "MemberServer"

			Path  = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name  = "PasswordLength"
			Value = 15
			SpecialValue = @{
				Type = "Range"
				Value = "15 or greater"
			}
		}
		@{
			Id    = "18.2.6"
			Task  = "Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'"
			Role = "MemberServer"

			Path  = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
			Name  = "PasswordAgeDays"
			Value = 30
			SpecialValue = @{
				Type = "Range"
				Value = "30 or less"
			}
		}

		# MS Security
		@{
			Id    = "18.3.4"
			Task  = "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
		
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
			Name  = "DisableExceptionChainValidation"
			Value = 0
		}
		@{
			Id    = "18.3.5"
			Task  = "Ensure 'Turn on Windows Defender protection against Potentially Unwanted Applications' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
			Name  = "MpEnablePus"
			Value = 1
		}

		# MSS
		@{
			Id    = "18.4.1"
			Task  = "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
			Name  = "AutoAdminLogon"
			Value = "0"
		}
		@{
			Id    = "18.4.5"
			Task  = "Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
		
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
			Name  = "KeepAliveTime"
			Value = 300000
		}
		@{
			Id    = "18.4.7"
			Task  = "Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
		
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
			Name  = "PerformRouterDiscovery"
			Value = 0
		}
		@{
			Id    = "18.4.8"
			Task  = "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
		
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
			Name  = "SafeDllSearchMode"
			Value = 1
		}
		@{
			Id    = "18.4.9"
			Task  = "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
		
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
			Name  = "ScreenSaverGracePeriod"
			Value = 5
			SpecialValue = @{
				Type = "Range"
				Value = "5 seconds or less"
			}
		}
		@{
			Id    = "18.4.10"
			Task  = "Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
		
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
			Name  = "TcpMaxDataRetransmissions"
			Value = 3
		}
		@{
			Id    = "18.4.11"
			Task  = "Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
		
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
			Name  = "TcpMaxDataRetransmissions"
			Value = 3
		}
		@{
			Id    = "18.4.12"
			Task  = "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
		
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
			Name  = "WarningLevel"
			Value = 90
			SpecialValue = @{
				Type = "Range"
				Value = "90 percent or less"
			}
		}

		# Network
		@{
			Id    = "18.5.5.1"
			Task  = "Ensure 'Enable Font Providers' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "EnableFontProviders"
			Value = 0
		}
		@{
			Id    = "18.5.9.1 A"
			Task  = "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
			Name  = "AllowLLTDIOOnDomain"
			Value = 0
		}
		@{
			Id    = "18.5.9.1 B"
			Task  = "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
			Name  = "AllowLLTDIOOnPublicNet"
			Value = 0
		}
		@{
			Id    = "18.5.9.1 C"
			Task  = "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
			Name  = "EnableLLTDIO"
			Value = 0
		}
		@{
			Id    = "18.5.9.1 D"
			Task  = "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
			Name  = "ProhibitLLTDIOOnPrivateNet"
			Value = 0
		}
		@{
			Id    = "18.5.9.2 A"
			Task  = "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
			Name  = "AllowRspndrOnDomain"
			Value = 0
		}
		@{
			Id    = "18.5.9.2 B"
			Task  = "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
			Name  = "AllowRspndrOnPublicNet"
			Value = 0
		}
		@{
			Id    = "18.5.9.2 C"
			Task  = "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
			Name  = "EnableRspndr"
			Value = 0
		}
		@{
			Id    = "18.5.9.2 D"
			Task  = "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
			Name  = "ProhibitRspndrOnPrivateNet"
			Value = 0
		}
		@{
			Id    = "18.5.10.2"
			Task  = "Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
			Name  = "Disabled"
			Value = 1
		}
		@{
			Id    = "18.5.11.2"
			Task  = "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
			Name  = "NC_AllowNetBridge_NLA"
			Value = 0
		}
		@{
			Id    = "18.5.11.3"
			Task  = "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
			Name  = "NC_ShowSharedAccessUI"
			Value = 0
		}
		@{
			Id    = "18.5.11.4"
			Task  = "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
			Name  = "NC_StdDomainUserSetLocation"
			Value = 1
		}
		@{
			Id    = "18.5.20.1 A"
			Task  = "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
			Name  = "EnableRegistrars"
			Value = 0
		}
		@{
			Id    = "18.5.20.1 B"
			Task  = "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
			Name  = "DisableUPnPRegistrar"
			Value = 0
		}
		@{
			Id    = "18.5.20.1 C"
			Task  = "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
			Name  = "DisableInBand802DOT11Registrar"
			Value = 0
		}
		@{
			Id    = "18.5.20.1 D"
			Task  = "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
			Name  = "DisableFlashConfigRegistrar"
			Value = 0
		}
		@{
			Id    = "18.5.20.1 E"
			Task  = "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
			Name  = "DisableWPDRegistrar"
			Value = 0
		}
		@{
			Id    = "18.5.20.2"
			Task  = "Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
			Name  = "DisableWcnUi"
			Value = 1
		}
		@{
			Id    = "18.5.21.1"
			Task  = "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
			Name  = "fMinimizeConnections"
			Value = 1
		}
		@{
			Id    = "18.5.21.2"
			Task  = "Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
			Name  = "fBlockNonDomain"
			Value = 1
		}

		# System
		@{
			Id    = "18.8.4.1"
			Task  = "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
			Name  = "AllowProtectedCreds"
			Value = 1
		}
		@{
			Id    = "18.8.5.4"
			Task  = "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
			Name  = "HVCIMATRequired"
			Value = 1
		}
		@{
			Id    = "18.8.21.2"
			Task  = "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
			Name  = "NoBackgroundPolicy"
			Value = 0
		}
		@{
			Id    = "18.8.21.4"
			Task  = "Ensure 'Continue experiences on this device' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "EnableCdp"
			Value = 0
		}
		@{
			Id    = "18.8.21.5"
			Task  = "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name  = "DisableBkGndGroupPolicy"
			DoesNotExist = $true
		}
		@{
			Id    = "18.8.22.1.2"
			Task  = "Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
			Name  = "PreventHandwritingDataSharing"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.3"
			Task  = "Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
			Name  = "PreventHandwritingErrorReports"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.4"
			Task  = "Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
			Name  = "ExitOnMSICW"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.5"
			Task  = "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
			Name  = "NoWebServices"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.7"
			Task  = "Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
			Name  = "NoRegistration"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.8"
			Task  = "Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"
			Name  = "DisableContentFileUpdates"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.9"
			Task  = "Ensure 'Turn off the `"Order Prints`" picture task' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
			Name  = "NoOnlinePrintsWizard"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.10"
			Task  = "Ensure 'Turn off the `"Publish to Web`" task for files and folders' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
			Name  = "NoPublishingWizard"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.11"
			Task  = "Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
			Name  = "CEIP"
			Value = 2
		}
		@{
			Id    = "18.8.22.1.12"
			Task  = "Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
			Name  = "CEIPEnable"
			Value = 0
		}
		@{
			Id    = "18.8.22.1.13 A"
			Task  = "Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
			Name  = "Disabled"
			Value = 1
		}
		@{
			Id    = "18.8.22.1.13 B"
			Task  = "Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
			Name  = "DoReport"
			Value = 0
		}
		@{
			Id    = "18.8.25.1 A"
			Task  = "Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
		
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
			Name  = "DevicePKInitBehavior"
			Value = 0
		}
		@{
			Id    = "18.8.25.1 B"
			Task  = "Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
		
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
			Name  = "DevicePKInitEnabled"
			Value = 1
		}
		@{
			Id    = "18.8.26.1"
			Task  = "Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"
			Name  = "BlockUserInputMethodsForSignIn"
			Value = 1
		}
		@{
			Id    = "18.8.27.1"
			Task  = "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "BlockUserFromShowingAccountDetailsOnSignin"
			Value = 1
		}
		@{
			Id    = "18.8.27.3"
			Task  = "Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "DontEnumerateConnectedUsers"
			Value = 1
		}
		@{
			Id    = "18.8.27.5"
			Task  = "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "DisableLockScreenAppNotifications"
			Value = 1
		}
		@{
			Id    = "18.8.27.6"
			Task  = "Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "BlockDomainPicturePassword"
			Value = 1
		}
		@{
			Id    = "18.8.27.7"
			Task  = "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "AllowDomainPINLogon"
			Value = 0
		}
		# @{
		# 	Id    = "18.8.28.1"
		# 	Task  = "Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'"
		
		# 	Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions"
		# 	Name  = "MitigationOptions_FontBocking"
		# 	Value = 1000000000000
		# }
		@{
			Id    = "18.8.33.6.1"
			Task  = "Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
			Name  = "DCSettingIndex"
			Value = 0
		}
		@{
			Id    = "18.8.33.6.2"
			Task  = "Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
			Name  = "ACSettingIndex"
			Value = 0
		}
		@{
			Id    = "18.8.35.1"
			Task  = "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "fAllowUnsolicited"
			Value = 0
		}
		@{
			Id    = "18.8.35.2"
			Task  = "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "fAllowToGetHelp"
			Value = 0
		}
		@{
			Id    = "18.8.36.1"
			Task  = "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)"
			Role = "MemberServer", "StandaloneServer"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
			Name  = "EnableAuthEpResolution"
			Value = 1
		}
		@{
			Id    = "18.8.44.5.1"
			Task  = "Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
			Name  = "DisableQueryRemoteServer"
			Value = 0
		}
		@{
			Id    = "18.8.44.11.1"
			Task  = "Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
			Name  = "ScenarioExecutionEnabled"
			Value = 0
		}
		@{
			Id    = "18.8.46.1"
			Task  = "Ensure 'Turn off the advertising ID' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo"
			Name  = "DisabledByGroupPolicy"
			Value = 1
		}
		@{
			Id    = "18.8.49.1.1"
			Task  = "Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
			Name  = "Enabled"
			Value = 1
		}
		@{
			Id    = "18.8.49.1.2"
			Task  = "Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)"
			Role = "MemberServer"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
			Name  = "Enabled"
			Value = 0
		}

		# Windows Compontents
		@{
			Id    = "18.9.4.1"
			Task  = "Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
			Name  = "AllowSharedLocalAppData"
			Value = 0
		}
		@{
			Id    = "18.9.10.1"
			Task  = "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
			Name  = "EnhancedAntiSpoofing"
			Value = 1
		}
		@{
			Id    = "18.9.12.1"
			Task  = "Ensure 'Allow Use of Camera' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
			Name  = "AllowCamera"
			Value = 0
		}
		@{
			Id    = "18.9.13.1"
			Task  = "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
			Name  = "DisableWindowsConsumerFeatures"
			Value = 1
		}
		@{
			Id    = "18.9.14.1"
			Task  = "Ensure 'Require pin for pairing' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
			Name  = "RequirePinForPairing"
			Value = 1
		}
		@{
			Id    = "18.9.15.1"
			Task  = "Ensure 'Do not display the password reveal button' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
			Name  = "DisablePasswordReveal"
			Value = 1
		}
		@{
			Id    = "18.9.16.2"
			Task  = "Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
			Name  = "DisableEnterpriseAuthProxy"
			Value = 1
		}
		@{
			Id    = "18.9.16.3"
			Task  = "Ensure 'Disable pre-release features or settings' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
			Name  = "EnableConfigFlighting"
			Value = 0
		}
		@{
			Id    = "18.9.16.4"
			Task  = "Ensure 'Do not show feedback notifications' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
			Name  = "DoNotShowFeedbackNotifications"
			Value = 1
		}
		@{
			Id    = "18.9.16.5"
			Task  = "Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
			Name  = "AllowBuildPreview"
			Value = 0
		}
		@{
			Id    = "18.9.26.1.1"
			Task  = "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
			Name  = "Retention"
			Value = "0"
		}
		@{
			Id    = "18.9.26.2.1"
			Task  = "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
			Name  = "Retention"
			Value = "0"
		}
		@{
			Id    = "18.9.26.3.1"
			Task  = "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
			Name  = "Retention"
			Value = "0"
		}
		@{
			Id    = "18.9.26.3.2"
			Task  = "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
			Name  = "MaxSize"
			Value = 32768
			SpecialValue = @{
				Type = "Range"
				Value = "32768 or greater"
			}
		}
		@{
			Id    = "18.9.26.4.1"
			Task  = "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
			Name  = "Retention"
			Value = "0"
		}
		@{
			Id    = "18.9.39.2"
			Task  = "Ensure 'Turn off location' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
			Name  = "DisableLocation"
			Value = 1
		}
		@{
			Id    = "18.9.43.1"
			Task  = "Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"
			Name  = "AllowMessageSync"
			Value = 0
		}
		@{
			Id    = "18.9.44.1"
			Task  = "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
			Name  = "DisableUserAuth"
			Value = 1
		}
		@{
			Id    = "18.9.52.1"
			Task  = "Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
			Name  = "DisableFileSyncNGSC"
			Value = 1
		}
		@{
			Id    = "18.9.58.3.3.1"
			Task  = "Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "fDisableCcm"
			Value = 1
		}
		@{
			Id    = "18.9.58.3.3.3"
			Task  = "Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "fDisableLPT"
			Value = 1
		}
		@{
			Id    = "18.9.58.3.3.4"
			Task  = "Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "fDisablePNPRedir"
			Value = 1
		}
		@{
			Id    = "18.9.58.3.10.1"
			Task  = "Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "MaxIdleTime"
			Value = 900000
			SpecialValue = @{
				Type = "Range"
				Value = "900000 milliseconds or less"
			}
		}
		@{
			Id    = "18.9.58.3.10.2"
			Task  = "Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "MaxDisconnectionTime"
			Value = 60000
		}
		@{
			Id    = "18.9.58.3.11.1"
			Task  = "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "DeleteTempDirsOnExit"
			Value = 1
		}
		@{
			Id    = "18.9.58.3.11.2"
			Task  = "Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
			Name  = "PerSessionTempDir"
			Value = 1
		}
		@{
			Id    = "18.9.60.2"
			Task  = "Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
			Name  = "AllowCloudSearch"
			Value = 0
		}
		@{
			Id    = "18.9.65.1"
			Task  = "Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
			Name  = "NoGenTicket"
			Value = 1
		}
		# use Get-MpPreference

		@{
			Id    = "18.9.76.3.1"
			Task  = "Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
			Name  = "LocalSettingOverrideSpynetReporting"
			Value = 0
		}
		@{
			Id    = "18.9.76.3.2"
			Task  = "Ensure 'Join Microsoft MAPS' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
			Name  = "SpynetReporting"
			Value = 0
		}
		@{
			Id    = "18.9.76.7.1"
			Task  = "Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
			Name  = "DisableBehaviorMonitoring"
			Value = 0
		}
		@{
			Id    = "18.9.76.9.1"
			Task  = "Ensure 'Configure Watson events' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
			Name  = "DisableGenericRePorts"
			Value = 1
		}
		@{
			Id    = "18.9.76.10.1"
			Task  = "Ensure 'Scan removable drives' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
			Name  = "DisableRemovableDriveScanning"
			Value = 0
		}
		@{
			Id    = "18.9.76.10.2"
			Task  = "Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
			Name  = "DisableEmailScanning"
			Value = 0
		}
		@{
			Id    = "18.9.76.13.1.1"
			Task  = "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
			Name  = "ExploitGuard_ASR_Rules"
			Value = 1
		}
		@{
			Id    = "18.9.76.13.1.2 A"
			Task  = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
			Name  = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
			Value = "1"
		}
		@{
			Id    = "18.9.76.13.1.2 B"
			Task  = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
			Name  = "3b576869-a4ec-4529-8536-b80a7769e899"
			Value = "1"
		}
		@{
			Id    = "18.9.76.13.1.2 C"
			Task  = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
			Name  = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
			Value = "1"
		}
		@{
			Id    = "18.9.76.13.1.2 D"
			Task  = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
			Name  = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
			Value = "1"
		}
		@{
			Id    = "18.9.76.13.1.2 E"
			Task  = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
			Name  = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
			Value = "1"
		}
		@{
			Id    = "18.9.76.13.1.2 F"
			Task  = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
			Name  = "d3e037e1-3eb8-44c8-a917-57927947596d"
			Value = "1"
		}
		@{
			Id    = "18.9.76.13.1.2 G"
			Task  = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
			Name  = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
			Value = "1"
		}
		@{
			Id    = "18.9.76.13.3.1"
			Task  = "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
			Name  = "EnableNetworkProtection"
			Value = 1
		}
		@{
			Id    = "18.9.76.14"
			Task  = "Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
			Name  = "DisableAntiSpyware"
			Value = 0
		}
		@{ # found under Computer Configuration\Administrative Templates\Windows Components\Windows Security\App and browser protection
			Id    = "18.9.79.1.1"
			Task  = "Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
			Name  = "DisallowExploitProtectionOverride"
			Value = 1
		}
		@{
			Id    = "18.9.80.1.1 A"
			Task  = "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
		
			Path  = "HKLM:SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "EnableSmartScreen"
			Value = 1
		}
		@{
			Id    = "18.9.80.1.1 B"
			Task  = "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
		
			Path  = "HKLM:SOFTWARE\Policies\Microsoft\Windows\System"
			Name  = "ShellSmartScreenLevel"
			Value = "Block"
		}
		@{
			Id    = "18.9.84.1"
			Task  = "Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
			Name  = "AllowSuggestedAppsInWindowsInkWorkspace"
			Value = 0
		}
		@{
			Id    = "18.9.84.2"
			Task  = "Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
			Name  = "AllowWindowsInkWorkspace"
			Value = 0
		}
		@{
			Id    = "18.9.95.2"
			Task  = "Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
			Name  = "EnableTranscripting"
			Value = 0
		}
		@{
			Id    = "18.9.97.2.2"
			Task  = "Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
			Name  = "AllowAutoConfig"
			Value = 0
		}
		@{
			Id    = "18.9.98.1"
			Task  = "Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"
			Name  = "AllowRemoteShellAccess"
			Value = 0
		}
		@{
			Id    = "18.9.101.1.1 A"
			Task  = "Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
			Name  = "ManagePreviewBuilds"
			Value = 1
		}
		
		@{
			Id    = "18.9.101.1.1 B"
			Task  = "Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
			Name  = "ManagePreviewBuildsPolicyValue"
			Value = 0
		}
		@{
			Id    = "18.9.101.1.2 A"
			Task  = "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
			Name  = "DeferFeatureUpdates"
			Value = 1
		}
		@{
			Id    = "18.9.101.1.2 B"
			Task  = "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
			Name  = "DeferFeatureUpdatesPeriodInDays"
			Value = 180
			SpecialValue = @{
				Type = "Range"
				Value = "180 days or greater"
			}
		}
		@{
			Id    = "18.9.101.1.2 C"
			Task  = "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
			Name  = "BranchReadinessLevel"
			Value = 32
		}
		@{
			Id    = "18.9.101.1.3 A"
			Task  = "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
			Name  = "DeferQualityUpdates"
			Value = 1
		}
		@{
			Id    = "18.9.101.1.3 B"
			Task  = "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
			Name  = "DeferQualityUpdatesPeriodInDays"
			Value = 0
		}
		@{
			Id    = "18.9.101.2"
			Task  = "Ensure 'Configure Automatic Updates' is set to 'Enabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
			Name  = "NoAutoUpdate"
			Value = 0
		}
		@{
			Id    = "18.9.101.3"
			Task  = "Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
			Name  = "ScheduledInstallDay"
			Value = 0
		}
		@{
			Id    = "18.9.101.4"
			Task  = "Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
		
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
			Name  = "NoAutoRebootWithLoggedOnUsers"
			Value = 0
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
			Id    = "2.3.1.1"
			Task  = "Ensure 'Accounts: Administrator account status' is set to 'Disabled' (MS only)"
			Role = "MemberServer"

			Policy = "EnableAdminAccount"
			Value = "0"
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
			Value = "Block"
		}
		@{
			Id = "9.1.3"
			Task = "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"

			Profile = "Domain"
			Setting = "DefaultOutboundAction"
			Value = "Allow"
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
			Value = 16384
			SpecialValue = @{
				Type = "Range"
				Value = "16384 KB or greater"
			}
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
			Value = "Block"
		}
		@{
			Id = "9.2.3"
			Task = "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"

			Profile = "Private"
			Setting = "DefaultOutboundAction"
			Value = "Allow"
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
			Value = 16384
			SpecialValue = @{
				Type = "Range"
				Value = "16384 KB or greater"
			}
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
			Value = "Block"
		}
		@{
			Id = "9.3.3"
			Task = "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"

			Profile = "Public"
			Setting = "DefaultOutboundAction"
			Value = "Allow"
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
			Value = 16384
			SpecialValue = @{
				Type = "Range"
				Value = "16384 KB or greater"
			}
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
	AuditPolicies = @(
		@{
			Id = "17.1.1"
			Task = "Credential Validation is set to Success and Failure"

			Subcategory = "Credential Validation"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.2.1"
			Task = "Application Group Management is set to Success and Failure"

			Subcategory = "Application Group Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.2.2"
			Task = "Computer Account Management is set to Success and Failure"

			Subcategory = "Computer Account Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.2.4"
			Task = "Other Account Management Events is set to Success and Failure"

			Subcategory = "Other Account Management Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.2.5"
			Task = "Security Group Management is set to Success and Failure"

			Subcategory = "Security Group Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.2.6"
			Task = "User Account Management is set to Success and Failure"

			Subcategory = "User Account Management"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.3.1"
			Task = "Plug and Play Events is set to Success"

			Subcategory = "Plug and Play Events"
			AuditFlag = 'Success'
		}
		@{
			Id = "17.3.2"
			Task = "Process Creation is set to Success"

			Subcategory = "Process Creation"
			AuditFlag = 'Success'
		}
		@{
			Id = "17.5.1"
			Task = "Account Lockout is set to Success and Failure"

			Subcategory = "Account Lockout"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.5.2"
			Task = "Group Membership is set to Success"

			Subcategory = "Group Membership"
			AuditFlag = 'Success'
		}
		@{
			Id = "17.5.3"
			Task = "Logoff is set to Success"

			Subcategory = "Logoff"
			AuditFlag = 'Success'
		}
		@{
			Id = "17.5.4"
			Task = "Logon is set to Success and Failure"

			Subcategory = "Logon"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.5.5"
			Task = "Other Logon/Logoff Events is set to Success and Failure"

			Subcategory = "Other Logon/Logoff Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.5.6"
			Task = "Special Logon is set to Success"

			Subcategory = "Special Logon"
			AuditFlag = 'Success'
		}
		@{
			Id = "17.6.1"
			Task = "Removable Storage is set to Success and Failure"

			Subcategory = "Removable Storage"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.7.1"
			Task = "Audit Policy Change is set to Success and Failure"

			Subcategory = "Audit Policy Change"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.7.2"
			Task = "Authentication Policy Change is set to Success"

			Subcategory = "Authentication Policy Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "17.7.3"
			Task = "Authorization Policy Change is set to Success"

			Subcategory = "Authorization Policy Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "17.8.1"
			Task = "Sensitive Privilege Use is set to Success and Failure"

			Subcategory = "Sensitive Privilege Use"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.9.1"
			Task = "IPsec Driver is set to Success and Failure"

			Subcategory = "IPsec Driver"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.9.2"
			Task = "Other System Events is set to Success and Failure"

			Subcategory = "Other System Events"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.9.3"
			Task = "Security State Change is set to Success"

			Subcategory = "Security State Change"
			AuditFlag = 'Success'
		}
		@{
			Id = "17.9.4"
			Task = "Security System Extension is set to Success and Failure"

			Subcategory = "Security System Extension"
			AuditFlag = 'Success and Failure'
		}
		@{
			Id = "17.9.5"
			Task = "System Integrity is set to Success and Failure"

			Subcategory = "System Integrity"
			AuditFlag = 'Success and Failure'
		}
	)
}