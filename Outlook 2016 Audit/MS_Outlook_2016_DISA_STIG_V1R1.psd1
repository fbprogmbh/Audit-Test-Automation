# Requirements for Microsoft Outlook 2016 DISA STIG V1R2
# Created at 03/19/2019 01:00:35

@{
	RegistrySettings = @(
		@{
			Id    = "DTOO111"
			Task  = "Enabling IE Bind to Object functionality must be present."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO117"
			Task  = "Saved from URL mark to assure Internet zone processing must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO123"
			Task  = "Navigation to URLs embedded in Office products must be blocked."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO124"
			Task  = "Scripted Window Security must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO126"
			Task  = "Add-on Management functionality must be allowed."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO129"
			Task  = "Links that invoke instances of Internet Explorer from within an Office product must be blocked."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO132"
			Task  = "File Downloads must be configured for proper restrictions."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO209"
			Task  = "Protection from zone elevation must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO211"
			Task  = "ActiveX Installs must be configured for proper restriction."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "outlook.exe"
			Value = 1
		}
		@{
			Id    = "DTOO216"
			Task  = "Publishing calendars to Office Online must be prevented."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal"
			Name  = "DisableOfficeOnline"
			Value = 1
		}
		@{
			Id    = "DTOO217"
			Task  = "Publishing to a Web Distributed and Authoring (DAV) server must be prevented."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal"
			Name  = "DisableDav"
			Value = 1
		}
		@{
			Id    = "DTOO218"
			Task  = "Level of calendar details that a user can publish must be restricted."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal"
			Name  = "PublishCalendarDetailsPolicy"
			Value = 16384
		}
		@{
			Id    = "DTOO219"
			Task  = "Access restriction settings for published calendars must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal"
			Name  = "RestrictedAccessOnly"
			Value = 1
		}
		@{
			Id    = "DTOO232"
			Task  = "Outlook Object Model scripts must be disallowed to run for shared folders."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "SharedFolderScript"
			Value = 0
		}
		@{
			Id    = "DTOO233"
			Task  = "Outlook Object Model scripts must be disallowed to run for public folders."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "PublicFolderScript"
			Value = 0
		}
		@{
			Id    = "DTOO234"
			Task  = "ActiveX One-Off forms must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "AllowActiveXOneOffForms"
			Value = 0
		}
		@{
			Id    = "DTOO236"
			Task  = "The Add-In Trust Level must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "AddinTrust"
			Value = 1
		}
		@{
			Id    = "DTOO237"
			Task  = "The remember password for internet e-mail accounts must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "EnableRememberPwd"
			Value = 0
		}
		@{
			Id    = "DTOO238"
			Task  = "Users customizing attachment security settings must be prevented."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook"
			Name  = "DisallowAttachmentCustomization"
			Value = 1
		}
		@{
			Id    = "DTOO239"
			Task  = "Outlook Security Mode must be configured to use Group Policy settings."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "AdminSecurityMode"
			Value = 3
		}
		@{
			Id    = "DTOO240"
			Task  = "The ability to display level 1 attachments must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "ShowLevel1Attach"
			Value = 0
		}<#
		@{
			Id    = "DTOO244"
			Task  = "Level 1 file extensions must be blocked and not removed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security\FileExtensionsRemoveLevel1"
			DoesNotExist = $true
		}
		@{
			Id    = "DTOO245"
			Task  = "Level 2 file extensions must be blocked and not removed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security\FileExtensionsRemoveLevel2"
			DoesNotExist = $true
		}#>
		@{
			Id    = "DTOO246"
			Task  = "Scripts in One-Off Outlook forms must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "EnableOneOffFormScripts"
			Value = 0
		}
		@{
			Id    = "DTOO247"
			Task  = "Custom Outlook Object Model (OOM) action execution prompts must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "PromptOOMCustomAction"
			Value = 0
		}
		@{
			Id    = "DTOO249"
			Task  = "Object Model Prompt for programmatic email send behavior must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "PromptOOMSend"
			Value = 0
		}
		@{
			Id    = "DTOO250"
			Task  = "Object Model Prompt behavior for programmatic address books must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "PromptOOMAddressBookAccess"
			Value = 0
		}
		@{
			Id    = "DTOO251"
			Task  = "Object Model Prompt behavior for programmatic access of user address data must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "PromptOOMAddressInformationAccess"
			Value = 0
		}
		@{
			Id    = "DTOO252"
			Task  = "Object Model Prompt behavior for Meeting and Task Responses must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "PromptOOMMeetingTaskRequestResponse"
			Value = 0
		}
		@{
			Id    = "DTOO253"
			Task  = "Object Model Prompt behavior for the SaveAs method must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "PromptOOMSaveAs"
			Value = 0
		}
		@{
			Id    = "DTOO254"
			Task  = "Object Model Prompt behavior for accessing User Property Formula must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "PromptOOMFormulaAccess"
			Value = 0
		}<#
		@{
			Id    = "DTOO256"
			Task  = "Trusted add-ins behavior for email must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\security"
			Name  = "trustedaddins"
			DoesNotExist = $true
		}#>
		@{
			Id    = "DTOO257"
			Task  = "S/Mime interoperability with external clients for message handling must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "ExternalSMime"
			Value = 0
		}
		@{
			Id    = "DTOO260"
			Task  = "Message formats must be set to use SMime."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "MsgFormats"
			Value = 1
		}
		@{
			Id    = "DTOO262"
			Task  = "Run in FIPS compliant mode must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "FIPSMode"
			Value = 1
		}
		@{
			Id    = "DTOO264"
			Task  = "Send all signed messages as clear signed messages must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "ClearSign"
			Value = 1
		}
		@{
			Id    = "DTOO266"
			Task  = "Automatic sending  s/Mime receipt requests must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "RespondToReceiptRequests"
			Value = 2
		}
		@{
			Id    = "DTOO267"
			Task  = "Retrieving of CRL data must be set for online action."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "UseCRLChasing"
			Value = 1
		}
		@{
			Id    = "DTOO270"
			Task  = "External content and pictures in HTML email must be displayed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\mail"
			Name  = "BlockExtContent"
			Value = 1
		}
		@{
			Id    = "DTOO271"
			Task  = "Automatic download content for email in Safe Senders list must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\mail"
			Name  = "UnblockSpecificSenders"
			Value = 0
		}
		@{
			Id    = "DTOO272"
			Task  = "Permit download of content from safe zones must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\mail"
			Name  = "UnblockSafeZone"
			Value = 1
		}
		@{
			Id    = "DTOO273"
			Task  = "IE Trusted Zones assumed trusted must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\mail"
			Name  = "TrustedZone"
			Value = 0
		}
		@{
			Id    = "DTOO274"
			Task  = "Internet with Safe Zones for Picture Download must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\mail"
			Name  = "Internet"
			Value = 0
		}
		@{
			Id    = "DTOO275"
			Task  = "Intranet with Safe Zones for automatic picture downloads must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\mail"
			Name  = "Intranet"
			Value = 0
		}
		@{
			Id    = "DTOO276"
			Task  = "Always warn on untrusted macros must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "Level"
			Value = 3
		}
		@{
			Id    = "DTOO277"
			Task  = "Hyperlinks in suspected phishing email messages must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\mail"
			Name  = "JunkMailEnableLinks"
			Value = 0
		}
		@{
			Id    = "DTOO279"
			Task  = "RPC encryption between Outlook and Exchange server must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\rpc"
			Name  = "EnableRPCEncryption"
			Value = 1
		}
		@{
			Id    = "DTOO280"
			Task  = "Outlook must be configured to force authentication when connecting to an Exchange server."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "AuthenticationService"
			Value = 16
            #16  or 10 (hex)
		}
		@{
			Id    = "DTOO283"
			Task  = "Disabling download full text of articles as HTML must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\rss"
			Name  = "EnableFullTextHTML"
			Value = 0
		}
		@{
			Id    = "DTOO284"
			Task  = "Automatic download of Internet Calendar appointment attachments must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\webcal"
			Name  = "EnableAttachments"
			Value = 0
		}
		@{
			Id    = "DTOO285"
			Task  = "Internet calendar integration in Outlook must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\webcal"
			Name  = "Disable"
			Value = 1
		}
		@{
			Id    = "DTOO286"
			Task  = "User Entries to Server List must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\meetings\profile"
			Name  = "ServerUI"
			Value = 2
		}
		@{
			Id    = "DTOO313"
			Task  = "Automatically downloading enclosures on RSS must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\rss"
			Name  = "EnableAttachments"
			Value = 0
		}
		@{
			Id    = "DTOO315"
			Task  = "Outlook must be configured not to prompt users to choose security settings if default settings fail."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "ForceDefaultProfile"
			Value = 0
		}
		@{
			Id    = "DTOO316"
			Task  = "Outlook minimum encryption key length settings must be set."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "MinEncKey"
			Value = 168
            #a8 (hex) or 168
		}
		@{
			Id    = "DTOO317"
			Task  = "Replies or forwards to signed/encrypted messages must be signed/encrypted."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "NoCheckOnSessionSecurity"
			Value = 1
		}
		@{
			Id    = "DTOO320"
			Task  = "Check e-mail addresses against addresses of certificates being used must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security"
			Name  = "SupressNameChecks"
			Value = 1
		}
	)
}
