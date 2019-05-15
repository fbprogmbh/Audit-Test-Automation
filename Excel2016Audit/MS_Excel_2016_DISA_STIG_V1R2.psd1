# Requirements for Microsoft Excel 2016 DISA STIG V1R2
# Created at 03/19/2019 00:45:19

@{
	RegistrySettings = @(
		@{
			Id    = "DTOO104"
			Task  = "Disabling of user name and password syntax from being used in URLs must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO105"
			Task  = "Open/Save actions for Excel 4 macrosheets and add-in files must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "XL4Macros"
			Value = 2
		}
		@{
			Id    = "DTOO106"
			Task  = "Open/Save actions for Excel 4 workbooks must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "XL4Workbooks"
			Value = 2
		}
		@{
			Id    = "DTOO107"
			Task  = "Open/Save actions for Excel 4 worksheets must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "XL4Worksheets"
			Value = 2
		}
		@{
			Id    = "DTOO108"
			Task  = "Actions for Excel 95 workbooks must be configured to edit in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "XL95Workbooks"
			Value = 5
		}
		@{
			Id    = "DTOO109"
			Task  = "Actions for Excel 95-97 workbooks and templates must be configured to edit in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\office\16.0\excel\security\fileblock"
			Name  = "XL9597WorkbooksandTemplates"
			Value = 5
		}
		@{
			Id    = "DTOO110"
			Task  = "Blocking as default file block opening behavior must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "OpenInProtectedView"
			Value = 0
		}
		@{
			Id    = "DTOO111"
			Task  = "Enabling IE Bind to Object functionality must be present."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO112"
			Task  = "Open/Save actions for Dif and Sylk files must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "DifandSylkFiles"
			Value = 2
		}
		@{
			Id    = "DTOO113"
			Task  = "Open/Save actions for Excel 2 macrosheets and add-in files must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "XL2Macros"
			Value = 2
		}
		@{
			Id    = "DTOO114"
			Task  = "Open/Save actions for Excel 2 worksheets must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "XL2Worksheets"
			Value = 2
		}
		@{
			Id    = "DTOO115"
			Task  = "Open/Save actions for Excel 3 macrosheets and add-in files must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "XL3Macros"
			Value = 2
		}
		@{
			Id    = "DTOO116"
			Task  = "Open/Save actions for Excel 3 worksheets must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "XL3Worksheets"
			Value = 2
		}
		@{
			Id    = "DTOO117"
			Task  = "Saved from URL mark to assure Internet zone processing must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO119"
			Task  = "Configuration for file validation must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation"
			Name  = "EnableOnLoad"
			Value = 1
		}
		@{
			Id    = "DTOO120"
			Task  = "Open/Save actions for web pages and Excel 2003 XML spreadsheets must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "HtmlandXmlssFiles"
			Value = 2
		}
		@{
			Id    = "DTOO121"
			Task  = "Files from the Internet zone must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview"
			Name  = "DisableInternetFilesInPV "
			Value = 0  
            DoesNotExist = $true 
		}
		@{
			Id    = "DTOO122"
			Task  = "Open/Save actions for dBase III / IV files must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock"
			Name  = "DBaseFiles"
			Value = 2
		}
		@{
			Id    = "DTOO123"
			Task  = "Navigation to URLs embedded in Office products must be blocked."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO124"
			Task  = "Scripted Window Security must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO126"
			Task  = "Add-on Management functionality must be allowed."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO127"
			Task  = "Add-ins to Office applications must be signed by a Trusted Publisher."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security"
			Name  = "RequireAddinSig"
			Value = 1
		}
		@{
			Id    = "DTOO129"
			Task  = "Links that invoke instances of Internet Explorer from within an Office product must be blocked."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO131"
			Task  = "Trust Bar Notifications for unsigned application add-ins must be blocked."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security"
			Name  = "NoTBPromptUnsignedAddin"
			Value = 1
		}
		@{
			Id    = "DTOO132"
			Task  = "File Downloads must be configured for proper restrictions."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO133"
			Task  = "All automatic loading from trusted locations must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations"
			Name  = "AllLocationsDisabled"
			Value = 1
		}
		@{
			Id    = "DTOO134"
			Task  = "Disallowance of trusted locations on the network must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations"
			Name  = "AllowNetworkLocations"
			Value = 0
		}
		@{
			Id    = "DTOO139"
			Task  = "The Save commands default file format must be configured."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\options"
			Name  = "DefaultFormat"
			Value = 51
		}
		@{
			Id    = "DTOO142"
			Task  = "The scanning of encrypted macros in open XML documents must be enforced."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security"
			Name  = "ExcelBypassEncryptedMacroScan "
			Value = 0
            DoesNotExist = $true
		}
		@{
			Id    = "DTOO145"
			Task  = "Macro storage must be in personal macro workbooks."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\options\binaryoptions"
			Name  = "fGlobalSheet_37_1"
			Value = 1
		}
		@{
			Id    = "DTOO146"
			Task  = "Trust access for VBA must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security"
			Name  = "AccessVBOM"
			Value = 0
		}
		@{
			Id    = "DTOO209"
			Task  = "Protection from zone elevation must be enforced."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO211"
			Task  = "ActiveX Installs must be configured for proper restriction."
			Path  = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "excel.exe"
			Value = 1
		}
		@{
			Id    = "DTOO288"
			Task  = "Files in unsafe locations must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview"
			Name  = "DisableUnsafeLocationsInPV "
			Value = 0 
            DoesNotExist = $true
		}
		@{
			Id    = "DTOO292"
			Task  = "Document behavior if file validation fails must be set."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation"
			Name  = "openinprotectedview "
			Value = 1  
            DoesNotExist = $true
		}
        @{
			Id    = "DTOO292_b"
			Task  = "Document behavior if file validation fails must be set."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation"
			Name  = "DisableEditFromPV "
			Value = 1  
		}
		@{
			Id    = "DTOO293"
			Task  = "Excel attachments opened from Outlook must be in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\security\protectedview"
			Name  = "DisableAttachmentsInPV "
			Value = 0
		}
		@{
			Id    = "DTOO304"
			Task  = "Warning Bar settings for VBA macros must be configured."
			Path  = "HKCU:\software\policies\Microsoft\office\16.0\excel\security"
			Name  = "vbawarnings"
			Value = 2    
            # Values of REG_DWORD = 3 or 4 are also acceptable values.
		}
		@{
			Id    = "DTOO418"
			Task  = "WEBSERVICE functions must be disabled."
			Path  = "HKCU:\software\policies\Microsoft\office\16.0\excel\security"
			Name  = "webservicefunctionwarnings "
			Value = 1 
            DoesNotExist = $true
            # If the value is REG_DWORD = 0 or 2, then this is a finding.
		}
		@{
			Id    = "DTOO419"
			Task  = "Corrupt workbook options must be disallowed."
			Path  = "HKCU:\software\policies\Microsoft\office\16.0\excel\options"
			Name  = "extractdatadisableui"
			Value = 1
		}
		@{
			Id    = "DTOO600"
			Task  = "Macros must be blocked from running in Office files from the Internet."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security"
			Name  = "blockcontentexecutionfrominternet"
			Value = 1
		}
		@{
			Id    = "DTOO605"
			Task  = "Files on local Intranet UNC must be opened in Protected View."
			Path  = "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview"
			Name  = "DisableIntranetCheck"
			Value = 0
		}
	)
}
