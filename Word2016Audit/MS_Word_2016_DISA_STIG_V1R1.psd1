# Requirements for Microsoft Word 2016 DISA STIG V1R1 
# Created at 03/19/2019 00:22:23

@{
	RegistrySettings = @(
		@{
			Id    = "DTOO104"
			Task  = "Disabling of user name and password syntax from being used in URLs must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO110"
			Task  = "Blocking as default file block opening behavior must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\fileblock"
			Name  = "OpenInProtectedView"
			Value = 0
		}
		@{
			Id    = "DTOO111"
			Task  = "The Internet Explorer Bind to Object functionality must be enabled."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO117"
			Task  = "Saved from URL mark to assure Internet zone processing must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO119"
			Task  = "Configuration for file validation must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\filevalidation"
			Name  = "EnableOnLoad"
			Value = 1
		}
		@{
			Id    = "DTOO121"
			Task  = "Files from the Internet zone must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\protectedview"
			Name  = "DisableInternetFilesInPV"
			Value = 0
		}
		@{
			Id    = "DTOO123"
			Task  = "Navigation to URLs embedded in Office products must be blocked."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO124"
			Task  = "Scripted Window Security must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO126"
			Task  = "Add-on Management functionality must be allowed."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO127"
			Task  = "Add-ins to Office applications must be signed by a Trusted Publisher."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security"
			Name  = "RequireAddinSig"
			Value = 1
		}
		@{
			Id    = "DTOO129"
			Task  = "Links that invoke instances of Internet Explorer from within an Office product must be blocked."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO131"
			Task  = "Trust Bar Notifications for unsigned application add-ins must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security"
			Name  = "NoTBPromptUnsignedAddin"
			Value = 1
		}
		@{
			Id    = "DTOO132"
			Task  = "File Downloads must be configured for proper restrictions."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "of winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO133"
			Task  = "All automatic loading from trusted locations must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\trusted locations"
			Name  = "AllLocationsDisabled"
			Value = 1
		}
		@{
			Id    = "DTOO134"
			Task  = "Disallowance of trusted locations on the network must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\trusted locations"
			Name  = "AllowNetworkLocations"
			Value = 0
		}
		@{
			Id    = "DTOO139"
			Task  = "The Save commands default file format must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\options"
			Name  = "DefaultFormat"
			Value = "(blank)"
		}
		@{
			Id    = "DTOO142"
			Task  = "Force encrypted macros to be scanned in open XML documents must be determined and configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security"
			Name  = "WordBypassEncryptedMacroScan"
			Value = 0
            DoesNotExist = $true
		}
		@{
			Id    = "DTOO146"
			Task  = "Trust access for VBA must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security"
			Name  = "AccessVBOM"
			Value = 0
		}
		@{
			Id    = "DTOO209"
			Task  = "Protection from zone elevation must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO211"
			Task  = "ActiveX Installs must be configured for proper restriction."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "winword.exe"
			Value = 1
		}
		@{
			Id    = "DTOO288"
			Task  = "Files in unsafe locations must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\protectedview"
			Name  = "DisableUnsafeLocationsInPV"
			Value = 0 
            DoesNotExist = $true
		}
		@{
			Id    = "DTOO292"
			Task  = "Document behavior if file validation fails must be set."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\security\filevalidation"
			Name  = "openinprotectedview"
			Value = 1  
            DoesNotExist = $true
		}
		@{
			Id    = "DTOO292_b"
			Task  = "Document behavior if file validation fails must be set."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\security\filevalidation"
			Name  = "DisableEditFromPV"
			Value = 1  
		}
		@{
			Id    = "DTOO293"
			Task  = "Attachments opened from Outlook must be in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\protectedview"
			Name  = "DisableAttachmentsInPV"
			Value = 0
		}
		@{
			Id    = "DTOO302"
			Task  = "The automatically update links feature must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\options"
			Name  = "DontUpdateLinks"
			Value = 1
		}
		@{
			Id    = "DTOO304"
			Task  = "Warning Bar settings for VBA macros must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security"
			Name  = "VBAWarnings"
			Value = 2    
			# Values of REG_DWORD = 3 or 4 are also acceptable values.
		}
		@{
			Id    = "DTOO328"
			Task  = "Online translation dictionaries must not be used."
			Path  = "HKCU\software\policies\Microsoft\office\16.0\common\research\translation"
			Name  = "useonline"
			Value = 0
		}
		@{
			Id    = "DTOO333"
			Task  = "Word 2 and earlier binary documents and templates must be blocked for open/save."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\fileblock"
			Name  = "Word2Files"
			Value = 2
		}
		@{
			Id    = "DTOO334"
			Task  = "Word 2000 binary documents and templates must be configured to edit in protected view."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\fileblock"
			Name  = "Word2000Files"
			Value = 5
		}
		@{
			Id    = "DTOO336"
			Task  = "Word 6.0 binary documents and templates must be configured for block open/save actions."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\fileblock"
			Name  = "Word60Files"
			Value = 2
		}
		@{
			Id    = "DTOO337"
			Task  = "Word 95 binary documents and templates must be configured to edit in protected view."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\fileblock"
			Name  = "Word95Files"
			Value = 5
		}
		@{
			Id    = "DTOO338"
			Task  = "Word 97 binary documents and templates must be configured to edit in protected view."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\fileblock"
			Name  = "Word97Files"
			Value = 5
		}
		@{
			Id    = "DTOO339"
			Task  = "Word XP binary documents and templates must be configured to edit in protected view."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security\fileblock"
			Name  = "WordXPFiles"
			Value = 5
		}
		@{
			Id    = "DTOO600"
			Task  = "Macros must be blocked from running in Office files from the Internet."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\word\security"
			Name  = "blockcontentexecutionfrominternet"
			Value = 1
		}
		@{
			Id    = "DTOO605"
			Task  = "Files on local Intranet UNC must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\security\protectedview"
			Name  = "DisableIntranetCheck"
			Value = 0
		}
	)
}
