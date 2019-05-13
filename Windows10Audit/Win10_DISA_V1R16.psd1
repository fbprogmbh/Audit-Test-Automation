# DISA Requirements MS Windows 10 DISA STIG V1R16

@{
	RegistrySettings         = @(
		@{
			Id    = "WN10-CC-000310"#450
			Task  = "Users must be prevented from changing installation options."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
			Name  = "EnableUserControl"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000315"#460
			Task  = "The Windows Installer Always install with elevated privileges must be disabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
			Name  = "AlwaysInstallElevated"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000320"#470
			Task  = "Users must be notified if a web-based program attempts to install software."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
			Name  = "SafeForScripting"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000325"#480
			Task  = "Automatically signing in the last interactive user after a system-initiated restart must be disabled."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "DisableAutomaticRestartSignOn"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000330"#500
			Task  = "The Windows Remote Management (WinRM) client must not use Basic authentication."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
			Name  = "AllowBasic"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000335"#510
			Task  = "The Windows Remote Management (WinRM) client must not allow unencrypted traffic."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
			Name  = "AllowUnencryptedTraffic"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000340"#520
			Task  = "The Windows Remote Management (WinRM) client must not use Digest authentication."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
			Name  = "AllowDigest"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000345"#530
			Task  = "The Windows Remote Management (WinRM) service must not use Basic authentication."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
			Name  = "AllowBasic"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000350"#540
			Task  = "The Windows Remote Management (WinRM) service must not allow unencrypted traffic."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
			Name  = "AllowUnencryptedTraffic"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000355"#550
			Task  = "The Windows Remote Management (WinRM) service must not store RunAs credentials."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
			Name  = "DisableRunAs"
			Value = 1
		}
		@{
			Id    = "WN10-AU-000500"#CC-300
			Task  = "The Application event log size must be configured to 32768 KB or greater."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"
			Name  = "MaxSize"
			Value = 32768
		}
		@{
			Id    = "WN10-AU-000505"#CC
			Task  = "The Security event log size must be configured to 1024000 KB or greater."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
			Name  = "MaxSize"
			Value = 1024000
		}
		@{
			Id    = "WN10-AU-000510"
			Task  = "The System event log size must be configured to 32768 KB or greater."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"
			Name  = "MaxSize"
			Value = 32768
		}
		@{
			Id    = "WN10-CC-000005"
			Task  = "Camera access from the lock screen must be disabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
			Name  = "NoLockScreenCamera"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000010"
			Task  = "The display of slide shows on the lock screen must be disabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
			Name  = "NoLockScreenSlideshow"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000020"
			Task  = "IPv6 source routing must be configured to highest protection."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
			Name  = "DisableIpSourceRouting"
			Value = 2
		}
		@{
			Id    = "WN10-CC-000025"
			Task  = "The system must be configured to prevent IP source routing."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
			Name  = "DisableIPSourceRouting"
			Value = 2
		}
		@{
			Id    = "WN10-CC-000030"
			Task  = "The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
			Name  = "EnableICMPRedirect"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000035"
			Task  = "The system must be configured to ignore NetBIOS name release requests except from WINS servers."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\"
			Name  = "NoNameReleaseOnDemand"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000040"
			Task  = "Insecure logons to an SMB server must be disabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
			Name  = "AllowInsecureGuestAuth"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000055"
			Task  = "Simultaneous connections to the Internet or a Windows domain must be limited."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\"
			Name  = "fMinimizeConnections"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000060"
			Task  = "Connections to non-domain networks when connected to a domain authenticated network must be blocked."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\"
			Name  = "fBlockNonDomain"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000065"
			Task  = "Wi-Fi Sense must be disabled."
			Path  = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\"
			Name  = "AutoConnectAllowedOEM"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000037"
			Task  = "Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "LocalAccountTokenFilterPolicy"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000085"
			Task  = "Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\"
			Name  = "DriverLoadPolicy"
			Value = 8
		}
		@{
			Id    = "WN10-CC-000090"
			Task  = "Group Policy objects must be reprocessed even if they have not changed."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
			Name  = "NoGPOListChanges"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000100"
			Task  = "Downloading print driver packages over HTTP must be prevented."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
			Name  = "DisableWebPnPDownload"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000015"
			Task  = "Local accounts with blank passwords must be restricted to prevent access from the network."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name  = "LimitBlankPasswordUse"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000105"
			Task  = "Web publishing and online ordering wizards must be prevented from downloading a list of providers."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
			Name  = "NoWebServices"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000110"
			Task  = "Printing over HTTP must be prevented."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
			Name  = "DisableHTTPPrinting"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000115"
			Task  = "Systems must at least attempt device authentication using certificates."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
			Name  = "DevicePKInitEnabled"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000120"
			Task  = "The network selection user interface (UI) must not be displayed on the logon screen."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
			Name  = "DontDisplayNetworkSelectionUI"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000130"
			Task  = "Local users on domain-joined computers must not be enumerated."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
			Name  = "EnumerateLocalUsers"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000030"
			Task  = "Audit policy using subcategories must be enabled."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name  = "SCENoApplyLegacyAuditPolicy"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000035"
			Task  = "Outgoing secure channel traffic must be encrypted or signed."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name  = "RequireSignOrSeal"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000040"
			Task  = "Outgoing secure channel traffic must be encrypted when possible."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name  = "SealSecureChannel"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000145"
			Task  = "Users must be prompted for a password on resume from sleep (on battery)."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
			Name  = "DCSettingIndex"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000045"
			Task  = "Outgoing secure channel traffic must be signed when possible."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name  = "SignSecureChannel"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000150"
			Task  = "The user must be prompted for a password on resume from sleep (plugged in)."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
			Name  = "ACSettingIndex"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000155"
			Task  = "Solicited Remote Assistance must not be allowed."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name  = "fAllowToGetHelp"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000050"
			Task  = "The computer account password must not be prevented from being reset."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name  = "DisablePasswordChange"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000165"
			Task  = "Unauthenticated RPC clients must be restricted from connecting to the RPC server."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
			Name  = "RestrictRemoteClients"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000170"
			Task  = "The setting to allow Microsoft accounts to be optional for modern style apps must be enabled."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "MSAOptional"
			Value = 1
		}
		<#@{
			Id    = "WN10-SO-000055"
			Task  = "The maximum age for machine account passwords must be configured to 30 days or less."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name  = "MaximumPasswordAge"
			Value = Please check data
		}#>
		@{
			Id    = "WN10-CC-000175"
			Task  = "The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"
			Name  = "DisableInventory"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000060"
			Task  = "The system must be configured to require a strong session key."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
			Name  = "RequireStrongKey"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000180"
			Task  = "Autoplay must be turned off for non-volume devices."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
			Name  = "NoAutoplayfornonVolume"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000070"
			Task  = "The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "InactivityTimeoutSecs"
			Value = 900
		}
		@{
			Id    = "WN10-CC-000185"
			Task  = "The default autorun behavior must be configured to prevent autorun commands."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
			Name  = "NoAutorun"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000190"
			Task  = "Autoplay must be disabled for all drives."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\"
			Name  = "NoDriveTypeAutoRun"
			Value = 255
		}
		<#@{
			Id    = "WN10-SO-000075"
			Task  = "The required legal notice must be configured to display before console logon."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "LegalNoticeText"
			Value =
		}#>
		@{
			Id    = "WN10-CC-000195"
			Task  = "Enhanced anti-spoofing for facial recognition must be enabled on Window 10."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\"
			Name  = "EnhancedAntiSpoofing"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000200"
			Task  = "Administrator accounts must not be enumerated during elevation."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"
			Name  = "EnumerateAdministrators"
			Value = 0
		}
		<#@{
			Id    = "WN10-SO-000080"
			Task  = "The Windows dialog box title for the legal banner must be configured."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "LegalNoticeCaption"
			Value = Please check data
		}
		@{
			Id    = "WN10-CC-000205"
			Task  = "Windows Telemetry must not be configured to Full."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
			Name  = "AllowTelemetry"
			Value = Please check data
		}
		@{
			Id    = "WN10-SO-000085"
			Task  = "Caching of logon credentials must be limited."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
			Name  = "CachedLogonsCount"
			Value = Please check data
		}#>
		@{
			Id    = "WN10-CC-000215"
			Task  = "Explorer Data Execution Prevention must be enabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
			Name  = "NoDataExecutionPrevention"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000220"
			Task  = "Turning off File Explorer heap termination on corruption must be disabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
			Name  = "NoHeapTerminationOnCorruption"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000225"
			Task  = "File Explorer shell protocol must run in protected mode."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
			Name  = "PreXPSP2ShellProtocolBehavior"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000095"
			Task  = "The Smart Card removal option must be configured to Force Logoff or Lock Workstation."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
			Name  = "SCRemoveOption"
			Value = "1"
		}
		@{
			Id    = "WN10-CC-000230"
			Task  = "Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\"
			Name  = "PreventOverride"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000235"
			Task  = "Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\"
			Name  = "PreventOverrideAppRepUnknown"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000100"
			Task  = "The Windows SMB client must be configured to always perform SMB packet signing."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
			Name  = "RequireSecuritySignature"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000240"
			Task  = "InPrivate browsing in Microsoft Edge must be disabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\"
			Name  = "AllowInPrivate"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000105"
			Task  = "The Windows SMB client must be enabled to perform SMB packet signing when possible."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
			Name  = "EnableSecuritySignature"
			Value = 1
		}
		<#@{
			Id    = "WN10-CC-000245"
			Task  = "The password manager function in the Edge browser must be disabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\"
			Name  = "FormSuggest Passwords"
			Value = Please check data
		}#>
		@{
			Id    = "WN10-SO-000110"
			Task  = "Unencrypted passwords must not be sent to third-party SMB Servers."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
			Name  = "EnablePlainTextPassword"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000250"
			Task  = "The Windows Defender SmartScreen filter for Microsoft Edge must be enabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\"
			Name  = "EnabledV9"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000255"
			Task  = "The use of a hardware security device with Windows Hello for Business must be enabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\"
			Name  = "RequireSecurityDevice"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000120"
			Task  = "The Windows SMB server must be configured to always perform SMB packet signing."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
			Name  = "RequireSecuritySignature"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000260"
			Task  = "Windows 10 must be configured to require a minimum pin length of six characters or greater."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\"
			Name  = "MinimumPINLength"
			Value = 6
		}
		@{
			Id    = "WN10-SO-000125"
			Task  = "The Windows SMB server must perform SMB packet signing when possible."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
			Name  = "EnableSecuritySignature"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000270"
			Task  = "Passwords must not be saved in the Remote Desktop Client."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name  = "DisablePasswordSaving"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000275"
			Task  = "Local drives must be prevented from sharing with Remote Desktop Session Hosts."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name  = "fDisableCdm"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000280"
			Task  = "Remote Desktop Services must always prompt a client for passwords upon connection."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name  = "fPromptForPassword"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000285"
			Task  = "The Remote Desktop Session Host must require secure RPC communications."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name  = "fEncryptRPCTraffic"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000290"
			Task  = "Remote Desktop Services must be configured with the client connection encryption set to the required level."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
			Name  = "MinEncryptionLevel"
			Value = 3
		}
		@{
			Id    = "WN10-CC-000295"
			Task  = "Attachments must be prevented from being downloaded from RSS feeds."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
			Name  = "DisableEnclosureDownload"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000145"
			Task  = "Anonymous enumeration of SAM accounts must not be allowed."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name  = "RestrictAnonymousSAM"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000300"
			Task  = "Basic authentication for RSS feeds over HTTP must not be used."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
			Name  = "AllowBasicAuthInClear"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000150"
			Task  = "Anonymous enumeration of shares must be restricted."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name  = "RestrictAnonymous"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000305"
			Task  = "Indexing of encrypted files must be turned off."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"
			Name  = "AllowIndexingEncryptedStoresOrItems"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000160"
			Task  = "The system must be configured to prevent anonymous users from having the same rights as the Everyone group."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name  = "EveryoneIncludesAnonymous"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000165"
			Task  = "Anonymous access to Named Pipes and Shares must be restricted."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
			Name  = "RestrictNullSessAccess"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000175"
			Task  = "Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\"
			Name  = "UseMachineId"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000180"
			Task  = "NTLM must be prevented from falling back to a Null session."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\"
			Name  = "allownullsessionfallback"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000185"
			Task  = "PKU2U authentication using online identities must be prevented."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
			Name  = "AllowOnlineID"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000190"
			Task  = "Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
			Name  = "SupportedEncryptionTypes"
			Value = 2147483640
		}
		@{
			Id    = "WN10-SO-000195"
			Task  = "The system must be configured to prevent the storage of the LAN Manager hash of passwords."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name  = "NoLMHash"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000205"
			Task  = "The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name  = "LmCompatibilityLevel"
			Value = 5
		}
		@{
			Id    = "WN10-SO-000210"
			Task  = "The system must be configured to the required LDAP client signing level."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\"
			Name  = "LDAPClientIntegrity"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000215"
			Task  = "The system must be configured to meet the minimum session security requirement for NTLM SSP based clients."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
			Name  = "NTLMMinClientSec"
			Value = 537395200
		}
		@{
			Id    = "WN10-SO-000220"
			Task  = "The system must be configured to meet the minimum session security requirement for NTLM SSP based servers."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
			Name  = "NTLMMinServerSec"
			Value = 537395200
		}
		@{
			Id    = "WN10-SO-000230"
			Task  = "The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"
			Name  = "Enabled"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000240"
			Task  = "The default permissions of global system objects must be increased."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\"
			Name  = "ProtectionMode"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000245"
			Task  = "User Account Control approval mode for the built-in Administrator must be enabled."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "FilterAdministratorToken"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000250"
			Task  = "User Account Control must, at minimum, prompt administrators for consent on the secure desktop."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "ConsentPromptBehaviorAdmin"
			Value = 2
		}
		@{
			Id    = "WN10-SO-000255"
			Task  = "User Account Control must automatically deny elevation requests for standard users."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "ConsentPromptBehaviorUser"
			Value = 0
		}
		@{
			Id    = "WN10-SO-000260"
			Task  = "User Account Control must be configured to detect application installations and prompt for elevation."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "EnableInstallerDetection"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000265"
			Task  = "User Account Control must only elevate UIAccess applications that are installed in secure locations."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "EnableSecureUIAPaths"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000270"
			Task  = "User Account Control must run all administrators in Admin Approval Mode, enabling UAC."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "EnableLUA"
			Value = 1
		}
		@{
			Id    = "WN10-SO-000275"
			Task  = "User Account Control must virtualize file and registry write failures to per-user locations."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
			Name  = "EnableVirtualization"
			Value = 1
		}
		@{
			Id    = "WN10-UC-000015"
			Task  = "Toast notifications to the lock screen must be turned off."
			Path  = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\"
			Name  = "NoToastApplicationNotificationOnLockScreen"
			Value = 1
		}
		@{
			Id    = "WN10-UC-000020"
			Task  = "Zone information must be preserved when saving attachments."
			Path  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
			Name  = "SaveZoneInformation"
			Value = 2
		}
		<#@{
			Id    = "WN10-CC-000206"
			Task  = "Windows Update must not obtain updates from other PCs on the Internet."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\"
			Name  = "DODownloadMode"
			Value = Please check data
		}#>
		@{
			Id    = "WN10-CC-000066"
			Task  = "Command line data must be included in process creation events."
			Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"
			Name  = "ProcessCreationIncludeCmdLine_Enabled"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000326"
			Task  = "PowerShell script block logging must be enabled."
			Path  = "HKLM:\SOFTWARE\ Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
			Name  = "EnableScriptBlockLogging"
			Value = 1
		}
		@{
			Id    = "WN10-00-000150"
			Task  = "Structured Exception Handling Overwrite Protection (SEHOP) must be enabled."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\"
			Name  = "DisableExceptionChainValidation"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000038"
			Task  = "WDigest Authentication must be disabled."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
			Name  = "UseLogonCredential"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000044"
			Task  = "Internet connection sharing must be disabled."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\"
			Name  = "NC_ShowSharedAccessUI"
			Value = 0
		}
		<#@{
			Id    = "WN10-SO-000167"
			Task  = "Remote calls to the Security Account Manager (SAM) must be restricted to Administrators."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
			Name  = "RestrictRemoteSAM"
			Value = Please check data
		}#>
		@{
			Id    = "WN10-CC-000197"
			Task  = "Microsoft consumer experiences must be turned off."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\"
			Name  = "DisableWindowsConsumerFeatures"
			Value = 1
		}
		<#@{
			Id    = "WN10-CC-000052"
			Task  = "Windows 10 must be configured to prioritize ECC Curves with longer key lengths first."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\ Cryptography\Configuration\SSL\00010002\"
			Name  = "EccCurves"
			Value = Please check data
		}#>
		@{
			Id    = "WN10-CC-000228"
			Task  = "Windows 10 must be configured to prevent Microsoft Edge browser data from being cleared on exit."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy\"
			Name  = "ClearBrowsingHistoryOnExit"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000252"
			Task  = "Windows 10 must be configured to disable Windows Game Recording and Broadcasting."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\"
			Name  = "AllowGameDVR"
			Value = 0
		}
		@{
			Id    = "WN10-CC-000068"
			Task  = "Windows 10 must be configured to enable Remote host allows delegation of non-exportable credentials."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"
			Name  = "AllowProtectedCreds"
			Value = 1
		}
		@{
			Id    = "WN10-00-000165"
			Task  = "The Server Message Block (SMB) v1 protocol must be disabled on the SMB server."
			Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
			Name  = "SMB1"
			Value = 0
		}
		@{
			Id    = "WN10-UC-000005"
			Task  = "The use of personal accounts for OneDrive synchronization must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\OneDrive\"
			Name  = "DisablePersonalSync"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000238"
			Task  = "Windows 10 must be configured to prevent certificate error overrides in Microsoft Edge."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\"
			Name  = "PreventCertErrorOverrides"
			Value = 1
		}
		@{
			Id    = "WN10-CC-000204"
			Task  = "If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows Analytics."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
			Name  = "LimitEnhancedDiagnosticDataWindowsAnalytics"
			Value = 1
		}
		<#@{
			Id    = "WN10-CC-000340"
			Task  = "OneDrive must only allow synchronizing of accounts for DoD organization instances."
			Path  = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\AllowTenantList\"
			Name  = "Organization's Tenant GUID"
			Value = Please check data
		}#>
	)
	UserRights               = @(
		@{
			Id       = 'WN10-UR-000005'
			Task     = "The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts."
			Policy   = "SeTrustedCredManAccessPrivilege"
			Identity = @()
		}
		@{
			Id       = 'WN10-UR-000010'
			Task     = 'The Access this computer from the network user right must only be assigned to the Administrators and Remote Desktop Users groups.'
			Policy   = "SeNetworkLogonRight"
			Identity = "Administrators", "Remote Desktop Users"
		}
		@{
			Id       = 'WN10-UR-000015'
			Task     = "The Act as part of the operating system user right must not be assigned to any groups or accounts."
			Policy   = "SeTcbPrivilege"
			Identity = @()
		}
		@{
			Id       = 'WN10-UR-000025'
			Task     = 'The Allow log on locally user right must only be assigned to the Administrators and Users groups.'
			Policy   = "SeInteractiveLogonRight"
			Identity = "Administrators", "Users"
		}
		@{
			Id       = 'WN10-UR-000030'
			Task     = "The Back up files and directories user right must only be assigned to the Administrators group."
			Policy   = "SeBackupPrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000035'
			Task     = 'The Change the system time user right must only be assigned to Administrators and Local Service.'
			Policy   = "SeSystemtimePrivilege"
			Identity = "Administrators", "Local Service"
		}
		@{
			Id       = 'WN10-UR-000040'
			Task     = "The Create a pagefile user right must only be assigned to the Administrators group."
			Policy   = "SeCreatePagefilePrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000045'
			Task     = "The Create a token object user right must not be assigned to any groups or accounts."
			Policy   = "SeCreateTokenPrivilege"
			Identity = @()
		}
		@{
			Id       = 'WN10-UR-000050'
			Task     = "The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service."
			Policy   = "SeCreateGlobalPrivilege"
			Identity = "Administrators", "Service", "Local Service", "Network Service"
		}
		@{
			Id       = 'WN10-UR-000055'
			Task     = "The Create permanent shared objects user right must not be assigned to any groups or accounts."
			Policy   = "SeCreatePermanentPrivilege"
			Identity = @()
		}
		# @{
		# 	Id       = 'WN10-UR-000060'
		# 	Task     = "The Create symbolic links user right must only be assigned to the Administrators group."
		# 	Policy   = "SeCreateSymbolicLinkPrivilege"
		# 	Identity = "Administrators"
		# }
		@{
			Id       = 'WN10-UR-000065'
			Task     = "The Debug programs user right must only be assigned to the Administrators group."
			Policy   = "SeDebugPrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000070 MW'
			Task     = 'The Deny access to this computer from the network user right on workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.'
			Role     = "MemberWorkstation"
			Policy   = "SeDenyNetworkLogonRight"
			Identity = "Enterprise Admins", "Domain Admins", "Local account", "Guests"
		}
		@{
			Id       = 'WN10-UR-000070 SW'
			Task     = 'The Deny access to this computer from the network user right on workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.'
			Role     = "StandaloneWorkstation"
			Policy   = "SeDenyNetworkLogonRight"
			Identity = "Guests"
		}
		@{
			Id       = 'WN10-UR-000075 MW'
			Role     = "MemberWorkstation"
			Task     = 'The Deny log on as a batch job user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.'
			Policy   = "SeDenyBatchLogonRight"
			Identity = "Enterprise Admins", "Domain Admins"
		}
		@{
			Id       = 'WN10-UR-000080 MW'
			Role     = "MemberWorkstation"
			Task     = 'The Deny log on as a service user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.'
			Policy   = "SeDenyServiceLogonRight"
			Identity = "Enterprise Admins", "Domain Admins"
		}
		@{
			Id       = 'WN10-UR-000085 MW'
			Role     = "MemberWorkstation"
			Task     = 'The Deny log on locally user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.'
			Policy   = "SeDenyInteractiveLogonRight"
			Identity = "Enterprise Admins", "Domain Admins", "Guests"
		}
		@{
			Id       = 'WN10-UR-000085 SW'
			Role     = "StandaloneWorkstation"
			Task     = 'The Deny log on locally user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.'
			Policy   = "SeDenyInteractiveLogonRight"
			Identity = "Guests"
		}
		@{
			Id       = 'WN10-UR-000090 MW'
			Role     = "MemberWorkstation"
			Task     = 'The Deny log on through Remote Desktop Services user right on workstations must at a minimum be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.'
			Policy   = "SeDenyRemoteInteractiveLogonRight"
			Identity = "Enterprise Admins", "Domain Admins", "Local account", "Guests"
		}
		@{
			Id       = 'WN10-UR-000090 SW'
			Role     = "StandaloneWorkstation"
			Task     = 'The Deny log on through Remote Desktop Services user right on workstations must at a minimum be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.'
			Policy   = "SeDenyRemoteInteractiveLogonRight"
			Identity = "Guests"
		}
		@{
			Id       = 'WN10-UR-000100'
			Task     = "The Force shutdown from a remote system user right must only be assigned to the Administrators group."
			Policy   = "SeRemoteShutdownPrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000105'
			Task     = "The Generate security audits user right must only be assigned to Local Service and Network Service."
			Policy   = "SeAuditPrivilege"
			Identity = "Local Service", "Network Service"
		}
		@{
			Id       = 'WN10-UR-000110'
			Task     = "The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service."
			Policy   = "SeImpersonatePrivilege"
			Identity = "Administrators", "Service", "Local Service", "Network Service"
		}
		@{
			Id       = 'WN10-UR-000115'
			Task     = "The Increase scheduling priority user right must only be assigned to the Administrators group."
			Policy   = "SeIncreaseBasePriorityPrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000120'
			Task     = "The Load and unload device drivers user right must only be assigned to the Administrators group."
			Policy   = "SeLoadDriverPrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000125'
			Task     = "The Lock pages in memory user right must not be assigned to any groups or accounts."
			Policy   = "SeLockMemoryPrivilege"
			Identity = @()
		}
		@{
			Id       = 'WN10-UR-000130'
			Task     = "The Manage auditing and security log user right must only be assigned to the Administrators group."
			Policy   = "SeSecurityPrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000140'
			Task     = "The Modify firmware environment values user right must only be assigned to the Administrators group."
			Policy   = "SeSystemEnvironmentPrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000145'
			Task     = "The Perform volume maintenance tasks user right must only be assigned to the Administrators group."
			Policy   = "SeManageVolumePrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000150'
			Task     = "The Profile single process user right must only be assigned to the Administrators group."
			Policy   = "SeProfileSingleProcessPrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000160'
			Task     = "The Restore files and directories user right must only be assigned to the Administrators group."
			Policy   = "SeRestorePrivilege"
			Identity = "Administrators"
		}
		@{
			Id       = 'WN10-UR-000165'
			Task     = "The Take ownership of files or other objects user right must only be assigned to the Administrators group."
			Policy   = "SeTakeOwnershipPrivilege"
			Identity = "Administrators"
		}

	)
	AccountPolicies          = @(
		@{
			Id = "WN10-AC-000005"
			Task = "Windows 10 account lockout duration must be configured to 15 minutes or greater."

			Config = @{
				Type = "AccountPolicyConfig"
				Policy = "LockoutDuration"
				Value = @{
					Operation = "greater than or equal"
					Value = 15
				}
			}
		}

		@{
			Id = "WN10-AC-000010"
			Task = "The number of allowed bad logon attempts must be configured to 3 or less."

			Config = @{
				Type = "ComplexConfig"
				Operation = "AND"
				Configs = @(
					@{
						Type = "AccountPolicyConfig"
						Policy = "LockoutBadCount"
						Value = @{
							Operation = "less than or equal"
							Value = 3
						}
					}
					@{
						Type = "AccountPolicyConfig"
						Policy = "LockoutBadCount"
						Value = @{
							Operation = "not equal"
							Value = 0
						}
					}
				)
			}
		}
		@{
			Id = "WN10-AC-000015"
			Task = "The period of time before the bad logon counter is reset must be configured to 15 minutes."

			Config = @{
				Policy = "ResetLockoutCount"
				Value = @{
					Operation = "greater than or equal"
					Value = 15
				}
			}
		}
		@{
			Id = 'WN10-AC-000020'
			Task = "The password history must be configured to 24 passwords remembered."
			Config = @{
				Policy = "PasswordHistorySize"
				Value = @{
					Operation = "greater than or equal"
					Value = 24
				}
			}
		}
		@{
			Id = 'WN10-AC-000025'
			Task = "The maximum password age must be configured to 60 days or less."
			Config = @{
				Policy = "MaximumPasswordAge"
				Value = @{
					Operation = "less than or equal"
					Value = 60
				}
			}
		}

		@{
			Id = "WN10-AC-000030"
			Task = "The minimum password age must be configured to at least 1 day."

			Config = @{
				Policy = "MinimumPasswordAge"
				Value = @{
					Operation = "greater than or equal"
					Value = 1
				}
			}
		}
		@{
			Id = "WN10-AC-000035"
			Task = "Passwords must, at a minimum, be 14 characters."

			Config = @{
				Policy = "MinimumPasswordLength"
				Value = @{
					Operation = "greater than or equal"
					Value = 14
				}
			}
		}
		@{
			Id = "WN10-AC-000040"
			Task = "The built-in Microsoft password complexity filter must be enabled."

			Config = @{
				Policy = "PasswordComplexity"
				Value = @{
					Operation = "equals"
					Value = 1
				}
			}
		}
		@{
			Id = "WN10-AC-000045"
			Task = "Reversible password encryption must be disabled."

			Config = @{
				Policy = "ClearTextPassword"
				Value = @{
					Operation = "equals"
					Value = 0
				}
			}
		}
		@{
			Id     = 'WN10-SO-000140'
			Task   = "Anonymous SID/Name translation must not be allowed."
			Config = @{
				Policy = "LSAAnonymousNameLookup"
				Value  = @{
					Operation = "equals"
					Value = 0
				}
			}
		}
	)
	WindowsOptionalFeatures  = @(
		@{
			Id      = 'WN10-00-000100'
			Task    = 'Internet Information System (IIS) or its subcomponents must not be installed on a workstation.'

			Feature = "IIS-WebServer"
		}
		# @{ ???
		# 	Id      = 'WN10-00-000105'
		# 	Task    = 'Simple Network Management Protocol (SNMP) must not be installed on the system.'

		# 	Feature = ""
		# }
		@{
			Id      = 'WN10-00-000110'
			Task    = 'Simple TCP/IP Services must not be installed on the system.'

			Feature = "SimpleTCP"
		}
		@{
			Id      = 'WN10-00-000115'
			Task    = 'The Telnet Client must not be installed on the system.'

			Feature = "TelnetClient"
		}
		@{
			Id      = 'WN10-00-000120'
			Task    = 'The TFTP Client must not be installed on the system.'

			Feature = "TFTP"
		}

	)
	FileSystemPermissions    = @(
		@{
			Id = "WN10-AU-000515"
			Task = "Permissions for the Application event log must prevent access by non-privileged accounts."

			Target = "%SystemRoot%\System32\winevt\Logs\Application.evtx"
			PrincipalRights = @{
				"NT SERVICE\EventLog"    = "FullControl"
				"NT AUTHORITY\SYSTEM"    = "FullControl"
				"BUILTIN\Administrators" = "FullControl"
			}
		}
		@{
			Id = "WN10-AU-000520"
			Task = "Permissions for the Security event log must prevent access by non-privileged accounts."

			Target = "%SystemRoot%\System32\winevt\Logs\Security.evtx"
			PrincipalRights = @{
				"NT SERVICE\EventLog"    = "FullControl"
				"NT AUTHORITY\SYSTEM"    = "FullControl"
				"BUILTIN\Administrators" = "FullControl"
			}
		}
		@{
			Id = "WN10-AU-000525"
			Task = "Permissions for the System event log must prevent access by non-privileged accounts."

			Target = "%SystemRoot%\System32\winevt\Logs\System.evtx"
			PrincipalRights = @{
				"NT SERVICE\EventLog"    = "FullControl"
				"NT AUTHORITY\SYSTEM"    = "FullControl"
				"BUILTIN\Administrators" = "FullControl"
			}
		}
	)
	RegistryPermissions     = @(
		@{
			Id = "WN10-RG-000005 A"
			Task = "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained."

			Target = "HKLM:\SECURITY"
			PrincipalRights = @{
				"NT Authority\System"                                               = "FullControl"
				# "BUILTIN\Administrators"                                            = "Special"
			}
		}
		@{
			Id = "WN10-RG-000005 B"
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
			Id = "WN10-RG-000005 C"
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
