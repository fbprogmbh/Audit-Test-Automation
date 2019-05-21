# Requirements for Microsoft Powerpoint 2016 DISA STIG V1R1
# Created at 03/25/2019 16:52:39

@{
	RegistrySettings = @(
		@{
			Id    = "DTOO104"
			Task  = "Disabling of user name and password syntax from being used in URLs must be enforced in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO110"
			Task  = "Blocking as default file block opening behavior must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\fileblock"
			Name  = "OpenInProtectedView"
			Value = 0
		}
		@{
			Id    = "DTOO111"
			Task  = "The Internet Explorer Bind to Object functionality must be enabled in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO117"
			Task  = "The Saved from URL mark must be selected to enforce Internet zone processing in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO119"
			Task  = "Configuration for file validation must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\filevalidation"
			Name  = "EnableOnLoad"
			Value = 1
		}
		@{
			Id    = "DTOO121"
			Task  = "Files from the Internet zone must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview"
			Name  = "DisableInternetFilesInPV "
			Value = 0
			DoesNotExist = $true
		}
		@{
			Id    = "DTOO126"
			Task  = "Add-on Management functionality must be allowed in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO127"
			Task  = "Add-ins to Office applications must be signed by a Trusted Publisher."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security"
			Name  = "RequireAddinSig"
			Value = 1
		}
		@{
			Id    = "DTOO129"
			Task  = "Links that invoke instances of Internet Explorer from within an Office product must be blocked in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO131"
			Task  = "Trust Bar Notifications for unsigned application add-ins must be blocked."
			Path  = "HKCU:\software\policies\Microsoft\office\16.0\powerpoint\security"
			Name  = "notbpromptunsignedaddin"
			Value = 1
		}
		@{
			Id    = "DTOO132"
			Task  = "File Downloads must be configured for proper restrictions in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO133"
			Task  = "All automatic loading from trusted locations must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\trusted locations"
			Name  = "AllLocationsDisabled"
			Value = 1
		}
		@{
			Id    = "DTOO134"
			Task  = "Disallowance of trusted locations on the network must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\trusted locations"
			Name  = "AllowNetworkLocations"
			Value = 0
		}
		@{
			Id    = "DTOO139"
			Task  = "The Save commands default file format must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\options"
			Name  = "DefaultFormat"
			Value = 27 # or 1b hex
		}
		@{
			Id    = "DTOO142"
			Task  = "The scanning of encrypted macros in open XML documents must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security"
			Name  = "PowerPointBypassEncryptedMacroScan"
			Value = 0
			DoesNotExist = $true
		}
		@{
			Id    = "DTOO146"
			Task  = "Trust access for VBA must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security"
			Name  = "AccessVBOM"
			Value = 0
		}
		@{
			Id    = "DTOO209"
			Task  = "Protection from zone elevation must be enforced in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO211"
			Task  = "ActiveX Installs must be configured for proper restriction in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO289"
			Task  = "The ability to run programs from a PowerPoint presentation must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security"
			Name  = "RunPrograms"
			Value = 0
			DoesNotExist = $true
		}
		@{
			Id    = "DTOO293"
			Task  = "Attachments opened from Outlook must be in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview"
			Name  = "DisableAttachmentsInPV "
			Value = 0
		}
		@{
			Id    = "DTOO304"
			Task  = "Warning Bar settings for VBA macros must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\powerpoint\security"
			Name  = "VBAWarnings"
			Value = 2
            #TODO Values of REG_DWORD = 3 or 4 are also acceptable values.
		}
		@{
			Id    = "DTOO501"
			Task  = "Disabling of user name and password syntax from being used in URLs must be enforced in PowerPoint Viewer. "
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO502"
			Task  = "The Internet Explorer Bind to Object functionality must be enabled in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO503"
			Task  = "The Saved from URL mark must be selected to enforce Internet zone processing in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO504"
			Task  = "Navigation to URLs embedded in Office products must be blocked in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO505"
			Task  = "Scripted Window Security must be enforced in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO506"
			Task  = "Add-on Management functionality must be allowed in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO507"
			Task  = "Links that invoke instances of Internet Explorer from within an Office product must be blocked in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO509"
			Task  = "Protection from zone elevation must be enforced in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO510"
			Task  = "ActiveX Installs must be configured for proper restriction in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "pptview.exe"
			Value = 1
		}
		@{
			Id    = "DTOO600"
			Task  = "Macros must be blocked from running in Office files from the Internet."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\powerpoint\security"
			Name  = "blockcontentexecutionfrominternet"
			Value = 1
		}
		@{
			Id    = "DTOO123"
			Task  = "Navigation to URLs embedded in Office products must be blocked in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO124"
			Task  = "Scripted Window Security must be enforced in PowerPoint."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "powerpnt.exe"
			Value = 1
		}
		@{
			Id    = "DTOO288"
			Task  = "Files in unsafe locations must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview"
			Name  = "DisableUnsafeLocationsInPV"
			Value = 0
			DoesNotExist = $true
		}
		@{
			Id    = "DTOO292"
			Task  = "Document behavior if file validation fails must be set."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\filevalidation"
			Name  = "openinprotectedview "
			Value = 1
			DoesNotExist = $true
            # Depends on: If the value DisableEditFromPV is set to REG_DWORD = 1, this is not a finding. If the value is set to REG_DWORD = 0, this is a finding.
		}
		@{
			Id    = "DTOO605"
			Task  = "Files on local Intranet UNC must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\security\protectedview"
			Name  = "DisableIntranetCheck"
			Value = 0
		}
		@{
			Id    = "DTOO508"
			Task  = "File Downloads must be configured for proper restrictions in PowerPoint Viewer."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "pptview.exe"
			Value = 1
		}
	)
}
