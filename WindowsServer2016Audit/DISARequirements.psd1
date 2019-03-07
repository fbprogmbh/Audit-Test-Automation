@{
	RegistrySettings = @(
		@{
			Id = "WN16-CC-000280"
			Task = "Administrator accounts must not be enumerated during elevation."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"
			Name = "EnumerateAdministrators"
			Value = 0
		}
		@{
			Id = "WN16-CC-000010"
			Task = "The display of slide shows on the lock screen must be disabled."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
			Name = "NoLockScreenSlideshow"
			Value = 1
		}
		@{
			Id = "WN16-MS-000020"
			Task = "Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
			Name = "LocalAccountTokenFilterPolicy"
			Value = 0
		}
		@{
			Id = "WN16-CC-000030"
			Task = "WDigest Authentication must be disabled."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
			Name = "UseLogonCredential"
			Value = 0
		}
		@{
			Id = "WN16-CC-000040"
			Task = "Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
			Name = "DisableIPSourceRouting"
			Value = 2
		}
		@{
			Id = "WN16-CC-000050"
			Task = "Source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
			Name = "DisableIPSourceRouting"
			Value = 2
		}
		@{
			Id = "WN16-CC-000060"
			Task = "Windows Server 2016 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
			Name = "EnableICMPRedirect"
			Value = 0
		}
		@{
			Id = "WN16-CC-000070"
			Task = "Windows Server 2016 must be configured to ignore NetBIOS name release requests except from WINS servers."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\"
			Name = "NoNameReleaseOnDemand"
			Value = 1
		}
		@{
			Id = "WN16-CC-000080"
			Task = "Insecure logons to an SMB server must be disabled."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
			Name = "AllowInsecureGuestAuth"
			Value = 0
		}
		@{
			Id = "WN16-CC-000100"
			Task = "Command line data must be included in process creation events."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"
			Name = "ProcessCreationIncludeCmdLine_Enabled"
			Value = 1
		}
		@{
			Id = "WN16-CC-000140"
			Task = "Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\"
			Name = "DriverLoadPolicy"
			Value = 8
		}
		@{
			Id = "WN16-CC-000150"
			Task = "Group Policy objects must be reprocessed even if they have not changed."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"
			Name = "NoGPOListChanges"
			Value = 0
		}
		@{
			Id = "WN16-CC-000160"
			Task = "Downloading print driver packages over HTTP must be prevented."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
			Name = "DisableWebPnPDownload"
			Value = 1
		}
		@{
			Id = "WN16-CC-000170"
			Task = "Printing over HTTP must be prevented."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
			Name = "DisableHTTPPrinting"
			Value = 1
		}
		@{
			Id = "WN16-CC-000180"
			Task = "The network selection user interface (UI) must not be displayed on the logon screen."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
			Name = "DontDisplayNetworkSelectionUI"
			Value = 1
		}
		@{
			Id = "WN16-MS-000030"
			Task = "Local users on domain-joined computers must not be enumerated."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
			Name = "EnumerateLocalUsers"
			Value = 0
		}
		@{
			Id = "WN16-CC-000200"
			Task = "Windows Server 2016 must be configured to block untrusted fonts from loading."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\"
			Name = "MitigationOptions_FontBocking"
			Value = "1000000000000"
		}
		@{
			Id = "WN16-CC-000210"
			Task = "Users must be prompted to authenticate when the system wakes from sleep (on battery)."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
			Name = "DCSettingIndex"
			Value = 1
		}
		@{
			Id = "WN16-CC-000220"
			Task = "Users must be prompted to authenticate when the system wakes from sleep (plugged in)."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
			Name = "ACSettingIndex"
			Value = 1
		}
		@{
			Id = "WN16-MS-000040"
			Task = "Unauthenticated Remote Procedure Call (RPC) clients must be restricted from connecting to the RPC server."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
			Name = "RestrictRemoteClients"
			Value = 1
		}
		@{
			Id = "WN16-CC-000240"
			Task = "The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"
			Name = "DisableInventory"
			Value = 1
		}
		@{
			Id = "WN16-CC-000250"
			Task = "AutoPlay must be turned off for non-volume devices."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
			Name = "NoAutoplayfornonVolume"
			Value = 1
		}
		@{
			Id = "WN16-CC-000260"
			Task = "The default AutoRun behavior must be configured to prevent AutoRun commands."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
			Name = "NoAutorun"
			Value = 1
		}
		@{
			Id = "WN16-CC-000270"
			Task = "AutoPlay must be disabled for all drives."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\"
			Name = "NoDriveTypeAutoRun"
			Value = 255
		}
		@{
			Id = "WN16-CC-000290"
			Task = "Windows Telemetry must be configured to Security or Basic."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
			Name = "AllowTelemetry"
			Value = 0
		}
		@{
			Id = "WN16-CC-000300"
			Task = "The Application event log size must be configured to 32768 KB or greater."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"
			Name = "MaxSize"
			Value = 32768
		}
		@{
			Id = "WN16-CC-000310"
			Task = "The Security event log size must be configured to 196608 KB or greater."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
			Name = "MaxSize"
			Value = 196608
		}
		@{
			Id = "WN16-CC-000320"
			Task = "The System event log size must be configured to 32768 KB or greater."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"
			Name = "MaxSize"
			Value = 32768
		}
		@{
			Id = "WN16-CC-000330"
			Task = "Windows SmartScreen must be enabled."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
			Name = "EnableSmartScreen"
			Value = 1
		}
		@{
			Id = "WN16-CC-000340"
			Task = "Explorer Data Execution Prevention must be enabled."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
			Name = "NoDataExecutionPrevention"
			Value = 0
		}
		@{
			Id = "WN16-CC-000350"
			Task = "Turning off File Explorer heap termination on corruption must be disabled."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
			Name = "NoHeapTerminationOnCorruption"
			Value = 0
		}
		@{
			Id = "WN16-CC-000360"
			Task = "File Explorer shell protocol must run in protected mode."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
			Name = "PreXPSP2ShellProtocolBehavior"
			Value = 0
		}
		@{
			Id = "WN16-CC-000370"
			Task = "Passwords must not be saved in the Remote Desktop Client."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name = "DisablePasswordSaving"
			Value = 1
		}
		@{
			Id = "WN16-CC-000380"
			Task = "Local drives must be prevented from sharing with Remote Desktop Session Hosts."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name = "fDisableCdm"
			Value = 1
		}
		@{
			Id = "WN16-CC-000390"
			Task = "Remote Desktop Services must always prompt a client for passwords upon connection."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name = "fPromptForPassword"
			Value = 1
		}
		@{
			Id = "WN16-CC-000400"
			Task = "The Remote Desktop Session Host must require secure Remote Procedure Call (RPC) communications."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name = "fEncryptRPCTraffic"
			Value = 1
		}
		@{
			Id = "WN16-CC-000410"
			Task = "Remote Desktop Services must be configured with the client connection encryption set to High Level."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name = "MinEncryptionLevel"
			Value = 3
		}
		@{
			Id = "WN16-CC-000420"
			Task = "Attachments must be prevented from being downloaded from RSS feeds."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
			Name = "DisableEnclosureDownload"
			Value = 1
		}
		@{
			Id = "WN16-CC-000430"
			Task = "Basic authentication for RSS feeds over HTTP must not be used."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
			Name = "AllowBasicAuthInClear"
			Value = 0
		}
		@{
			Id = "WN16-CC-000440"
			Task = "Indexing of encrypted files must be turned off."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"
			Name = "AllowIndexingEncryptedStoresOrItems"
			Value = 0
		}
		@{
			Id = "WN16-CC-000450"
			Task = "Users must be prevented from changing installation options."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
			Name = "EnableUserControl"
			Value = 0
		}
		@{
			Id = "WN16-CC-000460"
			Task = "The Windows Installer Always install with elevated privileges option must be disabled."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
			Name = "AlwaysInstallElevated"
			Value = 0
		}
		@{
			Id = "WN16-CC-000470"
			Task = "Users must be notified if a web-based program attempts to install software."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
			Name = "SafeForScripting"
			Value = 0
		}
		@{
			Id = "WN16-CC-000480"
			Task = "Automatically signing in the last interactive user after a system-initiated restart must be disabled."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "DisableAutomaticRestartSignOn"
			Value = 1
		}
		@{
			Id = "WN16-CC-000490"
			Task = "PowerShell script block logging must be enabled."

			Path = "HKLM:\SOFTWARE\ Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
			Name = "EnableScriptBlockLogging"
			Value = 1
		}
		@{
			Id = "WN16-CC-000500"
			Task = "The Windows Remote Management (WinRM) client must not use Basic authentication."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
			Name = "AllowBasic"
			Value = 0
		}
		@{
			Id = "WN16-CC-000510"
			Task = "The Windows Remote Management (WinRM) client must not allow unencrypted traffic."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
			Name = "AllowUnencryptedTraffic"
			Value = 0
		}
		@{
			Id = "WN16-CC-000520"
			Task = "The Windows Remote Management (WinRM) client must not use Digest authentication."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
			Name = "AllowDigest"
			Value = 0
		}
		@{
			Id = "WN16-CC-000530"
			Task = "The Windows Remote Management (WinRM) service must not use Basic authentication."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
			Name = "AllowBasic"
			Value = 0
		}
		@{
			Id = "WN16-CC-000540"
			Task = "The Windows Remote Management (WinRM) service must not allow unencrypted traffic."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
			Name = "AllowUnencryptedTraffic"
			Value = 0
		}
		@{
			Id = "WN16-CC-000550"
			Task = "The Windows Remote Management (WinRM) service must not store RunAs credentials."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
			Name = "DisableRunAs"
			Value = 1
		}
		@{
			Id = "WN16-SO-000020"
			Task = "Local accounts with blank passwords must be restricted to prevent access from the network."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name = "LimitBlankPasswordUse"
			Value = 1
		}
		@{
			Id = "WN16-SO-000050"
			Task = "Audit policy using subcategories must be enabled."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name = "SCENoApplyLegacyAuditPolicy"
			Value = 1
		}
		@{
			Id = "WN16-DC-000320"
			Task = "Domain controllers must require LDAP access signing."
			Role = "PrimaryDomainController"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\"
			Name = "LDAPServerIntegrity"
			Value = 2
		}
		@{
			Id = "WN16-DC-000330"
			Task = "Domain controllers must be configured to allow reset of machine account passwords."
			Role = "PrimaryDomainController"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name = "RefusePasswordChange"
			Value = 0
		}
		@{
			Id = "WN16-SO-000080"
			Task = "Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled."
			Role = "MemberServer"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name = "RequireSignOrSeal"
			Value = 1
		}
		@{
			Id = "WN16-SO-000090"
			Task = "Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled."
			Role = "MemberServer"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name = "SealSecureChannel"
			Value = 1
		}
		@{
			Id = "WN16-SO-000100"
			Task = "Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled."
			Role = "MemberServer"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name = "SignSecureChannel"
			Value = 1
		}
		@{
			Id = "WN16-SO-000110"
			Task = "The computer account password must not be prevented from being reset."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name = "DisablePasswordChange"
			Value = 0
		}
		@{
			Id = "WN16-SO-000120"
			Task = "The maximum age for machine account passwords must be configured to 30 days or less."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name = "MaximumPasswordAge"
			Value = "30 days or less, but not 0"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-SO-000130"
			Task = "Windows Server 2016 must be configured to require a strong session key."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name = "RequireStrongKey"
			Value = 1
		}
		@{
			Id = "WN16-SO-000140"
			Task = "The machine inactivity limit must be set to 15 minutes, locking the system with the screen saver."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "InactivityTimeoutSecs"
			Value = "900 seconds or less, but not 0"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-SO-000150"
			Task = "The required legal notice must be configured to display before console logon."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "LegalNoticeText"
			Value = "LegalNoticeText"
			ValueType = "ValuePlaceholder"
		}
		@{
			Id = "WN16-SO-000160"
			Task = "The Windows dialog box title for the legal banner must be configured with the appropriate text."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "LegalNoticeCaption"
			Value = "LegalNoticeTitle"
			ValueType = "ValuePlaceholder"
		}
		@{
			Id = "WN16-MS-000050"
			Task = "Caching of logon credentials must be limited."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
			Name = "CachedLogonsCount"
			Value = "4 or less"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-SO-000190"
			Task = "The setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
			Name = "RequireSecuritySignature"
			Value = 1
		}
		@{
			Id = "WN16-SO-000200"
			Task = "The setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
			Name = "EnableSecuritySignature"
			Value = 1
		}
		@{
			Id = "WN16-SO-000210"
			Task = "Unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
			Name = "EnablePlainTextPassword"
			Value = 0
		}
		@{
			Id = "WN16-SO-000220"
			Task = "The amount of idle time required before suspending a session must be configured to 15 minutes or less."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
			Name = "autodisconnect"
			Value = "15 minutes or less" # Exclude 0
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-SO-000230"
			Task = "The setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
			Name = "RequireSecuritySignature"
			Value = 1
		}
		@{
			Id = "WN16-SO-000240"
			Task = "The setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
			Name = "EnableSecuritySignature"
			Value = 1
		}
		@{
			Id = "WN16-SO-000260"
			Task = "Anonymous enumeration of Security Account Manager (SAM) accounts must not be allowed."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name = "RestrictAnonymousSAM"
			Value = 1
		}
		@{
			Id = "WN16-SO-000270"
			Task = "Anonymous enumeration of shares must not be allowed."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name = "RestrictAnonymous"
			Value = 1
		}
		@{
			Id = "WN16-SO-000280"
			Task = "Windows Server 2016 must be configured to prevent the storage of passwords and credentials."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name = "DisableDomainCreds"
			Value = 1
		}
		@{
			Id = "WN16-SO-000290"
			Task = "Windows Server 2016 must be configured to prevent anonymous users from having the same permissions as the Everyone group."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name = "EveryoneIncludesAnonymous"
			Value = 0
		}
		@{
			Id = "WN16-SO-000300"
			Task = "Anonymous access to Named Pipes and Shares must be restricted."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
			Name = "RestrictNullSessAccess"
			Value = 1
		}
		@{
			Id = "WN16-MS-000310"
			Task = "Remote calls to the Security Account Manager (SAM) must be restricted to Administrators."
			Role = "MemberServer","StandaloneServer"

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\"
			Name = "RestrictRemoteSAM"
			Value = "O:BAG:BAD:(A;;RC;;;BA)"
		}
		@{
			Id = "WN16-SO-000320"
			Task = "Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\"
			Name = "UseMachineId"
			Value = 1
		}
		@{
			Id = "WN16-SO-000330"
			Task = "NTLM must be prevented from falling back to a Null session."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\"
			Name = "allownullsessionfallback"
			Value = 0
		}
		@{
			Id = "WN16-SO-000340"
			Task = "PKU2U authentication using online identities must be prevented."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
			Name = "AllowOnlineID"
			Value = 0
		}
		@{
			Id = "WN16-SO-000350"
			Task = "Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
			Name = "SupportedEncryptionTypes"
			Value = 2147483640
		}
		@{
			Id = "WN16-SO-000360"
			Task = "Windows Server 2016 must be configured to prevent the storage of the LAN Manager hash of passwords."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name = "NoLMHash"
			Value = 1
		}
		@{
			Id = "WN16-SO-000380"
			Task = "The LAN Manager authentication level must be set to send NTLMv2 response only and to refuse LM and NTLM."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name = "LmCompatibilityLevel"
			Value = 5
		}
		@{
			Id = "WN16-SO-000390"
			Task = "Windows Server 2016 must be configured to at least negotiate signing for LDAP client signing."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\"
			Name = "LDAPClientIntegrity"
			Value = 1
		}
		@{
			Id = "WN16-SO-000400"
			Task = "Session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
			Name = "NTLMMinClientSec"
			Value = 537395200
		}
		@{
			Id = "WN16-SO-000410"
			Task = "Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
			Name = "NTLMMinServerSec"
			Value = 537395200
		}
		@{
			Id = "WN16-SO-000420"
			Task = "Users must be required to enter a password to access private keys stored on the computer."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\"
			Name = "ForceKeyProtection"
			Value = 2
		}
		@{
			Id = "WN16-SO-000430"
			Task = "Windows Server 2016 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"
			Name = "Enabled"
			Value = 1
		}
		@{
			Id = "WN16-SO-000440"
			Task = "Windows Server 2016 must be configured to require case insensitivity for non-Windows subsystems."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\"
			Name = "ObCaseInsensitive"
			Value = 1
		}
		@{
			Id = "WN16-SO-000450"
			Task = "The default permissions of global system objects must be strengthened."

			Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\"
			Name = "ProtectionMode"
			Value = 1
		}
		@{
			Id = "WN16-SO-000460"
			Task = "User Account Control approval mode for the built-in Administrator must be enabled."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "FilterAdministratorToken"
			Value = 1
		}
		@{
			Id = "WN16-SO-000470"
			Task = "UIAccess applications must not be allowed to prompt for elevation without using the secure desktop."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "EnableUIADesktopToggle"
			Value = 0
		}
		@{
			Id = "WN16-SO-000480"
			Task = "User Account Control must, at a minimum, prompt administrators for consent on the secure desktop."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "ConsentPromptBehaviorAdmin"
			Value = 2
		}
		@{
			Id = "WN16-SO-000490"
			Task = "User Account Control must automatically deny standard user requests for elevation."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "ConsentPromptBehaviorUser"
			Value = 0
		}
		@{
			Id = "WN16-SO-000500"
			Task = "User Account Control must be configured to detect application installations and prompt for elevation."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "EnableInstallerDetection"
			Value = 1
		}
		@{
			Id = "WN16-SO-000510"
			Task = "User Account Control must only elevate UIAccess applications that are installed in secure locations."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "EnableSecureUIAPaths"
			Value = 1
		}
		@{
			Id = "WN16-SO-000520"
			Task = "User Account Control must run all administrators in Admin Approval Mode, enabling UAC."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "EnableLUA"
			Value = 1
		}
		@{
			Id = "WN16-SO-000530"
			Task = "User Account Control must virtualize file and registry write failures to per-user locations."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name = "EnableVirtualization"
			Value = 1
		}
		@{
			Id = "WN16-UC-000010"
			Task = "A screen saver must be enabled on the system."

			Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\"
			Name = "ScreenSaveActive"
			Value = "1"
		}
		@{
			Id = "WN16-UC-000020"
			Task = "The screen saver must be password protected."

			Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop\"
			Name = "ScreenSaverIsSecure"
			Value = "1"
		}
		@{
			Id = "WN16-UC-000030"
			Task = "Zone information must be preserved when saving attachments."

			Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
			Name = "SaveZoneInformation"
			Value = 2
		}
		@{
			Id = "WN16-SO-000180"
			Task = "The Smart Card removal option must be configured to Force Logoff or Lock Workstation."

			Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
			Name = "scremoveoption"
			Value = "1"
		}

		@{
			Id = "WN16-CC-000090 1"
			Task = "Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
			Name = "\\*\NETLOGON"
			Value = "RequireMutualAuthentication=1, RequireIntegrity=1"
		}
		@{
			Id = "WN16-CC-000090 2"
			Task = "Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
			Name = "\\*\SYSVOL"
			Value = "RequireMutualAuthentication=1, RequireIntegrity=1"
		}
		@{
			Id = "WN16-CC-000110 1"
			Task = "Virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\"
			Name = "EnableVirtualizationBasedSecurity"
			Value = 1
		}
		@{
			Id = "WN16-CC-000110 2"
			Task = "Virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\"
			Name = "RequirePlatformSecurityFeatures"
			Value = 1
		}
		@{
			Id = "WN16-CC-000120"
			Task = "Credential Guard must be running on domain-joined member servers."
			Role = "MemberServer"

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\"
			Name = "LsaCfgFlags"
			Value = 1
		}
		@{
			Id = "WN16-CC-000130"
			Task = "Virtualization-based protection of code integrity must be enabled on domain-joined systems."

			Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
			Name = "HypervisorEnforcedCodeIntegrity"
			Value = 1
		}
	)
	UserRights = @(
		@{
			Id = "WN16-UR-000010"
			Task = "The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts."

			Policy = "SeTrustedCredManAccessPrivilege"
			Identity = @()
		}
		@{
			Id = "WN16-DC-000340"
			Task = "The Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers."
			Role = "PrimaryDomainController"

			Policy = "SeNetworkLogonRight"
			Identity = "Administrators", "NT AUTHORITY\Authenticated Users" #, "Enterprise Domain Controllers"
		}
		@{
			Id = "WN16-MS-000340"
			Task = "The Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers."
			Role = "MemberServer", "StandaloneServer"

			Policy = "SeNetworkLogonRight"
			Identity = "Administrators", "NT AUTHORITY\Authenticated Users"
		}
		@{
			Id = "WN16-UR-000030"
			Task = "The Act as part of the operating system user right must not be assigned to any groups or accounts."

			Policy = "SeTcbPrivilege"
			Identity = @()
		}
		@{
			Id = "WN16-DC-000350"
			Task = "The Add workstations to domain user right must only be assigned to the Administrators group."
			Role = "PrimaryDomainController"

			Policy = "SeMachineAccountPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000050"
			Task = "The Allow log on locally user right must only be assigned to the Administrators group."

			Policy = "SeInteractiveLogonRight"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-DC-000360"
			Task = "The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group."
			Role = "PrimaryDomainController"

			Policy = "SeRemoteInteractiveLogonRight"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000070"
			Task = "The Back up files and directories user right must only be assigned to the Administrators group."

			Policy = "SeBackupPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000080"
			Task = "The Create a pagefile user right must only be assigned to the Administrators group."

			Policy = "SeCreatePagefilePrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000090"
			Task = "The Create a token object user right must not be assigned to any groups or accounts."

			Policy = "SeCreateTokenPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000100"
			Task = "The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service."

			Policy = "SeCreateGlobalPrivilege"
			Identity = "Administrators", "Service", "Local Service", "Network Service"
		}
		@{
			Id = "WN16-UR-000110"
			Task = "The Create permanent shared objects user right must not be assigned to any groups or accounts."

			Policy = "SeCreatePermanentPrivilege"
			Identity = @()
		}
		@{
			Id = "WN16-UR-000120"
			Task = "The Create symbolic links user right must only be assigned to the Administrators group."

			Policy = "SeCreateSymbolicLinkPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000130"
			Task = "The Debug programs user right must only be assigned to the Administrators group."

			Policy = "SeDebugPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-DC-000370"
			Task = "The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems."
			Role = "PrimaryDomainController"

			Policy = "SeDenyNetworkLogonRight"
			Identity = "Guests"
		}
		@{
			Id = "WN16-MS-000370 MS"
			Task = "The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems."
			Role = "MemberServer"

			Policy = "SeDenyNetworkLogonRight"
			# Old audit:     "Enterprise Admins", "Domain Admins", "Guests"
			# Old hardening: "Enterprise Admins", "Domain Admins", "Administrators", "Guests"
			Identity = "Enterprise Admins", "Domain Admins", "Administrators", "Guests"
		}
		@{
			Id = "WN16-MS-000370 SS"
			Task = "The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems."
			Role = "StandaloneServer"

			Policy = "SeDenyNetworkLogonRight"
			# Old audit:    "Guests"
			# Old hardening: "Administrators", "Guests"
			# Why are Administrators here?
			Identity = "Guests"
		}
		@{
			Id = "WN16-DC-000380"
			Task = "The Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access."
			Role = "PrimaryDomainController"

			Policy = "SeDenyBatchLogonRight"
			Identity = "Guests"
		}
		@{
			Id = "WN16-MS-000380 MS"
			Task = "The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems."
			Role = "MemberServer"

			Policy = "SeDenyBatchLogonRight"
			Identity = "Enterprise Admins", "Domain Admins", "Guests"
		}
		@{
			Id = "WN16-MS-000380 SS"
			Task = "The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems."
			Role = "StandaloneServer"

			Policy = "SeDenyBatchLogonRight"
			Identity = "Guests"
		}
		@{
			Id = "WN16-DC-000390"
			Task = "The Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers."
			Role = "PrimaryDomainController"

			Policy = "SeDenyServiceLogonRight"
			Identity = @()
		}
		@{
			Id = "WN16-MS-000390 MS"
			Task = "The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems. No other groups or accounts must be assigned this right."
			Role = "MemberServer"

			Policy = "SeDenyServiceLogonRight"
			Identity = "Enterprise Admins", "Domain Admins"
		}
		@{
			Id = "WN16-MS-000390 SS"
			Task = "The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems. No other groups or accounts must be assigned this right."
			Role = "StandaloneServer"

			Policy = "SeDenyServiceLogonRight"
			# Old audit:     @()
			# Old hardening: "Enterprise Admins"
			Identity = @()
		}
		@{
			Id = "WN16-DC-000400"
			Task = "The Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access."
			Role = "PrimaryDomainController"

			Policy = "SeDenyInteractiveLogonRight"
			Identity = "Guests"
		}
		@{
			Id = "WN16-MS-000400 MS"
			Task = "The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems."
			Role = "MemberServer"

			Policy = "SeDenyInteractiveLogonRight"
			Identity = "Enterprise Admins", "Domain Admins", "Guests"
		}
		@{
			Id = "WN16-MS-000400 SS"
			Task = "The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems and from unauthenticated access on all systems."
			Role = "StandaloneServer"

			Policy = "SeDenyInteractiveLogonRight"
			Identity = "Guests"
		}
		@{
			Id = "WN16-DC-000410"
			Task = "The Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access."
			Role = "PrimaryDomainController"

			Policy = "SeDenyRemoteInteractiveLogonRight"
			Identity = "Guests"
		}
		@{
			Id = "WN16-MS-000410 MS"
			Task = "The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and from unauthenticated access on all systems."
			Role = "MemberServer"

			Policy = "SeDenyRemoteInteractiveLogonRight"
			# Disa Recommendation add local account
			Identity = "Enterprise Admins", "Domain Admins", "Guests"
		}
		@{
			Id = "WN16-MS-000410 SS"
			Task = "The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems and from unauthenticated access on all systems."
			Role = "StandaloneServer"

			Policy = "SeDenyRemoteInteractiveLogonRight"
			Identity = "Guests"
		}
		@{
			Id = "WN16-DC-000420"
			Task = "The Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers."
			Role = "PrimaryDomainController"

			Policy = "SeEnableDelegationPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-MS-000420"
			Task = "The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on member servers."
			Role = "MemberServer", "StandaloneServer"

			Policy = "SeEnableDelegationPrivilege"
			Identity = @()
		}
		@{
			Id = "WN16-UR-000200"
			Task = "The Force shutdown from a remote system user right must only be assigned to the Administrators group."

			Policy = "SeRemoteShutdownPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000210"
			Task = "The Generate security audits user right must only be assigned to Local Service and Network Service."

			Policy = "SeAuditPrivilege"
			Identity = "Local Service", "Network Service"
		}
		@{
			Id = "WN16-UR-000220"
			Task = "The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service."

			Policy = "SeImpersonatePrivilege"
			Identity = "Administrators", "Service", "Local Service", "Network Service"
		}
		@{
			Id = "WN16-UR-000230"
			Task = "The Increase scheduling priority user right must only be assigned to the Administrators group."

			Policy = "SeIncreaseBasePriorityPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000240"
			Task = "The Load and unload device drivers user right must only be assigned to the Administrators group."

			Policy = "SeLoadDriverPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000250"
			Task = "The Lock pages in memory user right must not be assigned to any groups or accounts."

			Policy = "SeLockMemoryPrivilege"
			Identity = @()
		}
		@{
			Id = "WN16-UR-000260"
			Task = "The Manage auditing and security log user right must only be assigned to the Administrators group."

			Policy = "SeSecurityPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000270"
			Task = "The Modify firmware environment values user right must only be assigned to the Administrators group."

			Policy = "SeSystemEnvironmentPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000280"
			Task = "The Perform volume maintenance tasks user right must only be assigned to the Administrators group."

			# Old audit: checks SeSystemEnvironmentPrivilege
			Policy = "SeManageVolumePrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000290"
			Task = "The Profile single process user right must only be assigned to the Administrators group."

			Policy = "SeProfileSingleProcessPrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000300"
			Task = "The Restore files and directories user right must only be assigned to the Administrators group."

			Policy = "SeRestorePrivilege"
			Identity = "Administrators"
		}
		@{
			Id = "WN16-UR-000310"
			Task = "The Take ownership of files or other objects user right must only be assigned to the Administrators group."

			Policy = "SeTakeOwnershipPrivilege"
			Identity = "Administrators"
		}
	)
	AccountPolicies = @(
		@{
			Id = "WN16-AC-000010"
			Task = "Windows 2016 account lockout duration must be configured to 15 minutes or greater."

			Policy = "LockoutDuration"
			Value = "15 minutes or greater"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-AC-000020"
			Task = "The number of allowed bad logon attempts must be configured to three or less."

			Policy = "LockoutBadCount"
			# Old audit: 0 not excluded
			Value = "3 or less, but not 0"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-AC-000030"
			Task = "The period of time before the bad logon counter is reset must be configured to 15 minutes or greater."

			Policy = "ResetLockoutCount"
			Value = "15 minutes or greater"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-AC-000040"
			Task = "The password history must be configured to 24 passwords remembered."

			Policy = "PasswordHistorySize"
			# Old audit: only 24 is allowed
			Value = "24 or greater"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-AC-000050"
			Task = "The maximum password age must be configured to 60 days or less."

			Policy = "MaximumPasswordAge"
			Value = "60 days or less"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-AC-000060"
			Task = "The minimum password age must be configured to at least one day."

			Policy = "MinimumPasswordAge"
			Value = "1 day or greater"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-AC-000070"
			Task = "The minimum password length must be configured to 14 characters."

			Policy = "MinimumPasswordLength"
			Value = "14 characters or greater"
			ValueType = "ValueRange"
		}
		@{
			Id = "WN16-AC-000080"
			Task = "The built-in Windows password complexity policy must be enabled."

			Policy = "PasswordComplexity"
			Value = 1
		}
		@{
			Id = "WN16-AC-000090"
			Task = "Reversible password encryption must be disabled."

			Policy = "ClearTextPassword"
			Value = 0
		}
		@{
			Id = "WN16-SO-000250"
			Task = "Anonymous SID/Name translation must not be allowed."

			Policy = "LSAAnonymousNameLookup"
			Value = 0
		}
		# ...
		@{
			Id = "WN16-SO-000370"
			Task = "Windows Server 2016 must be configured to force users to log off when their allowed logon hours expire."

			Policy = "ForceLogoffWhenHourExpire"
			Value = 1
		}
	)
	WindowsFeatures = @(
		@{
			Id = "WN16-00-000350"
			Task = "The Fax Server role must not be installed."

			Feature = "Fax"
		}
		@{
			Id = "WN16-00-000360"
			Task = "The Microsoft FTP service must not be installed unless required."

			Feature = "Web-Ftp-Service"
		}
		@{
			Id = "WN16-00-000370"
			Task = "The Peer Name Resolution Protocol must not be installed."

			Feature = "PNRP"
		}
		@{
			Id = "WN16-00-000380"
			Task = "Simple TCP/IP Services must not be installed."

			Feature = "Simple-TCPIP"
		}
		@{
			Id = "WN16-00-000390"
			Task = "The Telnet Client must not be installed."

			Feature = "Telnet-Client"
		}
		@{
			Id = "WN16-00-000400"
			Task = "The TFTP Client must not be installed."

			Feature = "TFTP-Client"
		}
		@{
			Id = "WN16-00-000410"
			Task = "The Server Message Block (SMB) v1 protocol must be uninstalled."

			Feature = "FS-SMB1"
		}
		@{
			Id = "WN16-00-000420"
			Task = "Windows PowerShell 2.0 must not be installed."

			Feature = "PowerShell-v2"
		}
	)
	Permissions = @(
		@{
			Id = "WN16-AU-000030"
			Task = "Permissions for the Application event log must prevent access by non-privileged accounts."

			Target = "%SystemRoot%\System32\winevt\Logs\Application.evtx"
			PrincipalRights = @{
				"NT SERVICE\EventLog"    = "FullControl"
				"NT AUTHORITY\SYSTEM"    = "FullControl"
				"BUILTIN\Administrators" = "FullControl"
			}
		}
		@{
			Id = "WN16-AU-000040"
			Task = "Permissions for the Security event log must prevent access by non-privileged accounts."

			Target = "%SystemRoot%\System32\winevt\Logs\Security.evtx"
			PrincipalRights = @{
				"NT SERVICE\EventLog"    = "FullControl"
				"NT AUTHORITY\SYSTEM"    = "FullControl"
				"BUILTIN\Administrators" = "FullControl"
			}
		}
		@{
			Id = "WN16-AU-000050"
			Task = "Permissions for the System event log must prevent access by non-privileged accounts."

			Target = "%SystemRoot%\System32\winevt\Logs\System.evtx"
			PrincipalRights = @{
				"NT SERVICE\EventLog"    = "FullControl"
				"NT AUTHORITY\SYSTEM"    = "FullControl"
				"BUILTIN\Administrators" = "FullControl"
			}
		}
		@{
			Id = "WN16-AU-000060"
			Task = "Event Viewer must be protected from unauthorized modification and deletion."

			Target = "%SystemRoot%\System32\Eventvwr.exe"
			PrincipalRights = @{
				"NT SERVICE\TrustedInstaller"                                       = "FullControl"
				"NT Authority\System"                                               = "ReadAndExecute, Synchronize"
				"BUILTIN\Administrators"                                            = "ReadAndExecute, Synchronize"
				"BUILTIN\Users"                                                     = "ReadAndExecute, Synchronize"
				"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"            = "ReadAndExecute, Synchronize"
				"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" = "ReadAndExecute, Synchronize"
			}
		}
		@{
			Id = "WN16-00-000160"
			Task = "Permissions for the system drive root directory (usually C:\) must conform to minimum requirements."

			Target = "%SystemDrive%\"
			PrincipalRights = @{
				"NT Authority\System"    = "FullControl"
				"BUILTIN\Administrators" = "FullControl"
				"BUILTIN\Users"          = "ReadAndExecute, Synchronize", "CreateFiles", "CreateDirectories"
				"CREATOR OWNER"          = "FullControl"
			}
		}
		@{
			Id = "WN16-00-000170 A"
			Task = "Permissions for program file directories must conform to minimum requirements."

			Target = "%ProgramFiles%\"
			PrincipalRights = @{
				"NT SERVICE\TrustedInstaller"                                       = "FullControl"
				"NT Authority\System"                                               = "FullControl", "Modify, Synchronize"
				"BUILTIN\Administrators"                                            = "FullControl", "Modify, Synchronize"
				"BUILTIN\Users"                                                     = "ReadAndExecute, Synchronize"
				"CREATOR OWNER"                                                     = "FullControl"
				"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"            = "ReadAndExecute, Synchronize"
				"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" = "ReadAndExecute, Synchronize"
			}
		}
		@{
			Id = "WN16-00-000170 B"
			Task = "Permissions for program file directories must conform to minimum requirements."

			Target = "%ProgramFiles(x86)%\"
			PrincipalRights = @{
				"NT SERVICE\TrustedInstaller"                                       = "FullControl"
				"NT Authority\System"                                               = "FullControl", "Modify, Synchronize"
				"BUILTIN\Administrators"                                            = "FullControl", "Modify, Synchronize"
				"BUILTIN\Users"                                                     = "ReadAndExecute, Synchronize"
				"CREATOR OWNER"                                                     = "FullControl"
				"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"            = "ReadAndExecute, Synchronize"
				"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" = "ReadAndExecute, Synchronize"
			}
		}
		@{
			Id = "WN16-00-000180"
			Task = "Permissions for the Windows installation directory must conform to minimum requirements."

			Target = "%windir%\"
			PrincipalRights = @{
				"NT SERVICE\TrustedInstaller"                                       = "FullControl"
				"NT Authority\System"                                               = "FullControl", "Modify, Synchronize"
				"BUILTIN\Administrators"                                            = "FullControl", "Modify, Synchronize"
				"BUILTIN\Users"                                                     = "ReadAndExecute, Synchronize"
				"CREATOR OWNER"                                                     = "FullControl"
				"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"            = "ReadAndExecute, Synchronize"
				"APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" = "ReadAndExecute, Synchronize"
			}
		}
		@{
			Id = "WN16-00-000190 A"
			Task = "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained."

			Target = "HKLM:\SECURITY"
			PrincipalRights = @{
				"NT Authority\System"                                               = "FullControl"
				"BUILTIN\Administrators"                                            = "ReadPermissions, ChangePermissions"
			}
		}
		# Special user "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681"
		@{
			Id = "WN16-00-000190 B"
			Task = "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained."

			Target = "HKLM:\SOFTWARE"
			PrincipalRights = @{
				"BUILTIN\Users"                                                     = "ReadKey"
				"BUILTIN\Administrators"                                            = "FullControl"
				"NT Authority\System"                                               = "FullControl"
				"CREATOR OWNER"                                                     = "FullControl"
				"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"            = "ReadKey"
			}
		}
		@{
			Id = "WN16-00-000190 C"
			Task = "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained."

			Target = "HKLM:\SYSTEM"
			PrincipalRights = @{
				"BUILTIN\Users"                                                     = "ReadKey"
				"BUILTIN\Administrators"                                            = "FullControl"
				"NT Authority\System"                                               = "FullControl"
				"CREATOR OWNER"                                                     = "FullControl"
				"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"            = "ReadKey"
			}
		}
	)
}
