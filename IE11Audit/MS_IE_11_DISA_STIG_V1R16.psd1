# Requirements MS Internet Explorer 11 DISA STIG V1R16 

@{
	RegistrySettings = @(
		@{
			Id    = "DTBI014-IE11"
			Task  = "Turn off Encryption Support must be enabled."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "SecureProtocols"
			Value = 2560
		}
		@{
			Id    = "DTBI015-IE11"
			Task  = "The Internet Explorer warning about certificate address mismatch must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "WarnOnBadCertRecving"
			Value = 1
		}
        @{
			Id    = "DTBI018-IE11"
			Task  = "Check for publishers certificate revocation must be enforced."
			Path  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
			Name  = "State"
			Value = 146432
		}
		@{
			Id    = "DTBI022-IE11"
			Task  = "The Download signed ActiveX controls property must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1001"
			Value = 3
		}
		@{
			Id    = "DTBI023-IE11"
			Task  = "The Download unsigned ActiveX controls property must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1004"
			Value = 3
		}
		@{
			Id    = "DTBI024-IE11"
			Task  = "The Initialize and script ActiveX controls not marked as safe property must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1201"
			Value = 3
		}
		@{
			Id    = "DTBI030-IE11"
			Task  = "Font downloads must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1604"
			Value = 3
		}
		@{
			Id    = "DTBI031-IE11"
			Task  = "The Java permissions must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1C00"
			Value = 0
		}
		@{
			Id    = "DTBI032-IE11"
			Task  = "Accessing data sources across domains must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1406"
			Value = 3
		}
		@{
			Id    = "DTBI036-IE11"
			Task  = "Functionality to drag and drop or copy and paste files must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1802"
			Value = 3
		}
		@{
			Id    = "DTBI038-IE11"
			Task  = "Launching programs and files in IFRAME must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1804"
			Value = 3
		}
		@{
			Id    = "DTBI039-IE11"
			Task  = "Navigating windows and frames across different domains must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1607"
			Value = 3
		}
		@{
			Id    = "DTBI042-IE11"
			Task  = "Userdata persistence must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1606"
			Value = 3
		}
		@{
			Id    = "DTBI044-IE11"
			Task  = "Clipboard operations via script must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1407"
			Value = 3
		}
		@{
			Id    = "DTBI046-IE11"
			Task  = "Logon options must be configured to prompt (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1A00"
			Value = 65536
		}
		@{
			Id    = "DTBI061-IE11"
			Task  = "Java permissions must be configured with High Safety (Intranet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
			Name  = "1C00"
			Value = 65536
		}
		@{
			Id    = "DTBI091-IE11"
			Task  = "Java permissions must be configured with High Safety (Trusted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
			Name  = "1C00"
			Value = 65536
		}
		@{
			Id    = "DTBI1000-IE11"
			Task  = "Dragging of content from different domains within a window must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2708"
			Value = 3
		}
		@{
			Id    = "DTBI1005-IE11"
			Task  = "Dragging of content from different domains across windows must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2709"
			Value = 3
		}
		@{
			Id    = "DTBI1010-IE11"
			Task  = "Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI1020-IE11"
			Task  = "Internet Explorer Processes Restrict ActiveX Install must be enforced (iexplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI1025-IE11"
			Task  = "Dragging of content from different domains within a window must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2708"
			Value = 3
		}
		@{
			Id    = "DTBI112-IE11"
			Task  = "The Download signed ActiveX controls property must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1001"
			Value = 3
		}
		@{
			Id    = "DTBI113-IE11"
			Task  = "The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1004"
			Value = 3
		}
		@{
			Id    = "DTBI114-IE11"
			Task  = "The Initialize and script ActiveX controls not marked as safe property must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1201"
			Value = 3
		}
		@{
			Id    = "DTBI115-IE11"
			Task  = "ActiveX controls and plug-ins must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1200"
			Value = 3
		}
		@{
			Id    = "DTBI116-IE11"
			Task  = "ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1405"
			Value = 3
		}
		@{
			Id    = "DTBI119-IE11"
			Task  = "File downloads must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1803"
			Value = 3
		}
		@{
			Id    = "DTBI120-IE11"
			Task  = "Font downloads must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1604"
			Value = 3
		}
		@{
			Id    = "DTBI121-IE11"
			Task  = "Java permissions must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1C00"
			Value = 0
		}
		@{
			Id    = "DTBI122-IE11"
			Task  = "Accessing data sources across domains must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1406"
			Value = 3
		}
		@{
			Id    = "DTBI123-IE11"
			Task  = "The Allow META REFRESH property must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1608"
			Value = 3
		}
		@{
			Id    = "DTBI126-IE11"
			Task  = "Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1802"
			Value = 3
		}
		@{
			Id    = "DTBI128-IE11"
			Task  = "Launching programs and files in IFRAME must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1804"
			Value = 3
		}
		@{
			Id    = "DTBI129-IE11"
			Task  = "Navigating windows and frames across different domains must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1607"
			Value = 3
		}
		@{
			Id    = "DTBI132-IE11"
			Task  = "Userdata persistence must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1606"
			Value = 3
		}
		@{
			Id    = "DTBI133-IE11"
			Task  = "Active scripting must be disallowed (Restricted Sites Zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1400"
			Value = 3
		}
		@{
			Id    = "DTBI134-IE11"
			Task  = "Clipboard operations via script must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1407"
			Value = 3
		}
		@{
			Id    = "DTBI136-IE11"
			Task  = "Logon options must be configured and enforced (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1A00"
			Value = 196608
		}
		@{
			Id    = "DTBI300-IE11"
			Task  = "Configuring History setting must be set to 40 days."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History"
			Name  = "DaysToKeep"
			Value = 40
		}
		@{
			Id    = "DTBI318-IE11"
			Task  = "Internet Explorer must be set to disallow users to add/delete sites."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "Security_zones_map_edit"
			Value = 1
		}
		@{
			Id    = "DTBI319-IE11"
			Task  = "Internet Explorer must be configured to disallow users to change policies."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "Security_options_edit"
			Value = 1
		}
		@{
			Id    = "DTBI320-IE11"
			Task  = "Internet Explorer must be configured to use machine settings."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "Security_HKLM_only"
			Value = 1
		}
		@{
			Id    = "DTBI325-IE11"
			Task  = "Security checking features must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Security"
			Name  = "DisableSecuritySettingsCheck"
			Value = 0
		}
		@{
			Id    = "DTBI350-IE11"
			Task  = "Software must be disallowed to run or install with invalid signatures."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Download"
			Name  = "RunInvalidSignatures"
			Value = 0
		}
		@{
			Id    = "DTBI365-IE11"
			Task  = "Checking for server certificate revocation must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "CertificateRevocation"
			Value = 1
		}
		@{
			Id    = "DTBI370-IE11"
			Task  = "Checking for signatures on downloaded programs must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Download"
			Name  = "CheckExeSignatures"
			Value = "yes"
		}
		@{
			Id    = "DTBI375-IE11"
			Task  = "All network paths (UNCs) for Intranet sites must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
			Name  = "UNCAsIntranet"
			Value = 0
		}
		@{
			Id    = "DTBI385-IE11"
			Task  = "Script-initiated windows without size or position constraints must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2102"
			Value = 3
		}
		@{
			Id    = "DTBI390-IE11"
			Task  = "Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2102"
			Value = 3
		}
		@{
			Id    = "DTBI395-IE11"
			Task  = "Scriptlets must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1209"
			Value = 3
		}
		@{
			Id    = "DTBI415-IE11"
			Task  = "Automatic prompting for file downloads must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2200"
			Value = 3
		}
    	@{
			Id    = "DTBI425-IE11"
			Task  = "Java permissions must be disallowed (Local Machine zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"
			Name  = "1C00"
			Value = 0
		}
		@{
			Id    = "DTBI430-IE11"
			Task  = "Java permissions must be disallowed (Locked Down Local Machine zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0"
			Name  = "1C00"
			Value = 0
		}
		@{
			Id    = "DTBI435-IE11"
			Task  = "Java permissions must be disallowed (Locked Down Intranet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1"
			Name  = "1C00"
			Value = 0
		}
		@{
			Id    = "DTBI440-IE11"
			Task  = "Java permissions must be disallowed (Locked Down Trusted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2"
			Name  = "1C00"
			Value = 0
		}
        @{
			Id    = "DTBI450-IE11"
			Task  = "Java permissions must be disallowed (Locked Down Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4"
			Name  = "1C00"
			Value = 0
		}
		@{
			Id    = "DTBI455-IE11"
			Task  = "XAML files must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2402"
			Value = 3
		}
		@{
			Id    = "DTBI460-IE11"
			Task  = "XAML files must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2402"
			Value = 3
		}
		@{
			Id    = "DTBI485-IE11"
			Task  = "Protected Mode must be enforced (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2500"
			Value = 0
		}
		@{
			Id    = "DTBI490-IE11"
			Task  = "Protected Mode must be enforced (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2500"
			Value = 0
		}
		@{
			Id    = "DTBI495-IE11"
			Task  = "Pop-up Blocker must be enforced (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1809"
			Value = 0
		}
		@{
			Id    = "DTBI500-IE11"
			Task  = "Pop-up Blocker must be enforced (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1809"
			Value = 0
		}
		@{
			Id    = "DTBI515-IE11"
			Task  = "Websites in less privileged web content zones must be prevented from navigating into the Internet zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2101"
			Value = 3
		}
		@{
			Id    = "DTBI520-IE11"
			Task  = "Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2101"
			Value = 3
		}
		@{
			Id    = "DTBI575-IE11"
			Task  = "Allow binary and script behaviors must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2000"
			Value = 3
		}
		@{
			Id    = "DTBI580-IE11"
			Task  = "Automatic prompting for file downloads must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2200"
			Value = 3
		}
		@{
			Id    = "DTBI590-IE11"
			Task  = "Internet Explorer Processes for MIME handling must be enforced. (Reserved)"
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI592-IE11"
			Task  = "Internet Explorer Processes for MIME handling must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI594-IE11"
			Task  = "Internet Explorer Processes for MIME handling must be enforced (iexplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI595-IE11"
			Task  = "Internet Explorer Processes for MIME sniffing must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI596-IE11"
			Task  = "Internet Explorer Processes for MIME sniffing must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI597-IE11"
			Task  = "Internet Explorer Processes for MIME sniffing must be enforced (iexplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI599-IE11"
			Task  = "Internet Explorer Processes for MK protocol must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI600-IE11"
			Task  = "Internet Explorer Processes for MK protocol must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI605-IE11"
			Task  = "Internet Explorer Processes for MK protocol must be enforced (iexplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI610-IE11"
			Task  = "Internet Explorer Processes for Zone Elevation must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI612-IE11"
			Task  = "Internet Explorer Processes for Zone Elevation must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI614-IE11"
			Task  = "Internet Explorer Processes for Zone Elevation must be enforced (iexplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI630-IE11"
			Task  = "Internet Explorer Processes for Restrict File Download must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI635-IE11"
			Task  = "Internet Explorer Processes for Restrict File Download must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI640-IE11"
			Task  = "Internet Explorer Processes for Restrict File Download must be enforced (iexplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI645-IE11"
			Task  = "Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI647-IE11"
			Task  = "Internet Explorer Processes for restricting pop-up windows must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "explorer.exe" 
			Value = "1"
		}
		@{
			Id    = "DTBI649-IE11"
			Task  = "Internet Explorer Processes for restricting pop-up windows must be enforced (iexplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI650-IE11"
			Task  = ".NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Sites Zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2004"
			Value = 3
		}
		@{
			Id    = "DTBI655-IE11"
			Task  = ".NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2001"
			Value = 3
		}
		@{
			Id    = "DTBI670-IE11"
			Task  = "Scripting of Java applets must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1402"
			Value = 3
		}
		@{
			Id    = "DTBI690-IE11"
			Task  = "AutoComplete feature for forms must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "Use FormSuggest"
			Value = "no"
		}
        @{
			Id    = "DTBI715-IE11"
			Task  = "Crash Detection management must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions"
			Name  = "NoCrashDetection"
			Value = 1
		}
		@{
			Id    = "DTBI725-IE11"
			Task  = "Turn on the auto-complete feature for user names and passwords on forms must be disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "FormSuggest PW Ask"
			Value = "no"
		}
        @{
			Id    = "DTBI740-IE11"
			Task  = "Managing SmartScreen Filter use must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
			Name  = "EnabledV9"
			Value = 1
		}
		@{
			Id    = "DTBI760-IE11"
			Task  = "Browser must retain history on exit."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy"
			Name  = "ClearBrowsingHistoryOnExit"
			Value = 0
		}
		@{
			Id    = "DTBI770-IE11"
			Task  = "Deleting websites that the user has visited must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy"
			Name  = "CleanHistory"
			Value = 0
		}
		@{
			Id    = "DTBI780-IE11"
			Task  = "InPrivate Browsing must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy"
			Name  = "EnableInPrivateBrowsing"
			Value = 0
		}
		@{
			Id    = "DTBI800-IE11"
			Task  = "Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1206"
			Value = 3
		}
		@{
			Id    = "DTBI810-IE11"
			Task  = "When uploading files to a server, the local directory path must be excluded (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "160A"
			Value = 3
		}
		@{
			Id    = "DTBI815-IE11"
			Task  = "Internet Explorer Processes for Notification Bars must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI820-IE11"
			Task  = "Security Warning for unsafe files must be set to prompt (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1806"
			Value = 1
		}
		@{
			Id    = "DTBI825-IE11"
			Task  = "Internet Explorer Processes for Notification Bars must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI830-IE11"
			Task  = "ActiveX controls without prompt property must be used in approved domains only (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "120b"
			Value = 3
		}
		@{
			Id    = "DTBI835-IE11"
			Task  = "Internet Explorer Processes for Notification Bars must be enforced (iexplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI840-IE11"
			Task  = "Cross-Site Scripting Filter must be enforced (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1409"
			Value = 0
		}
		@{
			Id    = "DTBI850-IE11"
			Task  = "Scripting of Internet Explorer WebBrowser Control must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1206"
			Value = 3
		}
		@{
			Id    = "DTBI860-IE11"
			Task  = "When uploading files to a server, the local directory path must be excluded (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "160A"
			Value = 3
		}
		@{
			Id    = "DTBI870-IE11"
			Task  = "Security Warning for unsafe files must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1806"
			Value = 3
		}
		@{
			Id    = "DTBI880-IE11"
			Task  = "ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "120b"
			Value = 3
		}
		@{
			Id    = "DTBI890-IE11"
			Task  = "Cross-Site Scripting Filter property must be enforced (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1409"
			Value = 0
		}
		@{
			Id    = "DTBI900-IE11"
			Task  = "Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI910-IE11"
			Task  = "Status bar updates via script must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2103"
			Value = 3
		}
		@{
			Id    = "DTBI920-IE11"
			Task  = ".NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2004"
			Value = 3
		}
		@{
			Id    = "DTBI930-IE11"
			Task  = ".NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2001"
			Value = 3
		}
		@{
			Id    = "DTBI940-IE11"
			Task  = "Scriptlets must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1209"
			Value = 3
		}
		@{
			Id    = "DTBI950-IE11"
			Task  = "Status bar updates via script must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2103"
			Value = 3
		}
		@{
			Id    = "DTBI985-IE11"
			Task  = "When Enhanced Protected Mode is enabled, ActiveX controls must be disallowed to run in Protected Mode."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "DisableEPMCompat"
			Value = 1
		}
		@{
			Id    = "DTBI990-IE11"
			Task  = "Dragging of content from different domains across windows must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2709"
			Value = 3
		}
		@{
			Id    = "DTBI995-IE11"
			Task  = "Enhanced Protected Mode functionality must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "Isolation"
			Value = "PMEM"
		}
		@{
			Id    = "DTBI356-IE11"
			Task  = "The 64-bit tab processes, when running in Enhanced Protected Mode on 64-bit versions of Windows, must be turned on."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "Isolation64Bit"
			Value = 1
		}
		@{
			Id    = "DTBI1046-IE11"
			Task  = "Anti-Malware programs against ActiveX controls must be run for the Internet zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "270C"
			Value = 0
		}
		@{
			Id    = "DTBI062-IE11"
			Task  = "Anti-Malware programs against ActiveX controls must be run for the Intranet zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
			Name  = "270C"
			Value = 0
		}
		@{
			Id    = "DTBI426-IE11"
			Task  = "Anti-Malware programs against ActiveX controls must be run for the Local Machine zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"
			Name  = "270C"
			Value = 0
		}
		@{
			Id    = "DTBI1051-IE11"
			Task  = "Anti-Malware programs against ActiveX controls must be run for the Restricted Sites zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "270C"
			Value = 0
		}
		@{
			Id    = "DTBI092-IE11"
			Task  = "Anti-Malware programs against ActiveX controls must be run for the Trusted Sites zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
			Name  = "270C"
			Value = 0
		}
		@{
			Id    = "DTBI1060-IE11"
			Task  = "Prevent bypassing SmartScreen Filter warnings must be enabled."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
			Name  = "PreventOverride"
			Value = 1
		}
		@{
			Id    = "DTBI1065-IE11"
			Task  = "Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet must be enabled."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
			Name  = "PreventOverrideAppRepUnknown"
			Value = 1
		}
		@{
			Id    = "DTBI1070-IE11"
			Task  = "Prevent per-user installation of ActiveX controls must be enabled."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX"
			Name  = "BlockNonAdminActiveXInstall"
			Value = 1
		}
		@{
			Id    = "DTBI1075-IE11"
			Task  = "Prevent ignoring certificate errors option must be enabled."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "PreventIgnoreCertErrors"
			Value = 1
		}
		@{
			Id    = "DTBI1080-IE11"
			Task  = "Turn on SmartScreen Filter scan option for the Internet Zone must be enabled."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2301"
			Value = 0
		}
		@{
			Id    = "DTBI1085-IE11"
			Task  = "Turn on SmartScreen Filter scan option for the Restricted Sites Zone must be enabled."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2301"
			Value = 0
		}
		@{
			Id    = "DTBI1090-IE11"
			Task  = "The Initialize and script ActiveX controls not marked as safe must be disallowed (Intranet Zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
			Name  = "1201"
			Value = 3
		}
		@{
			Id    = "DTBI1095-IE11"
			Task  = "The Initialize and script ActiveX controls not marked as safe must be disallowed (Trusted Sites Zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
			Name  = "1201"
			Value = 3
		}
		@{
			Id    = "DTBI1100-IE11"
			Task  = "Allow Fallback to SSL 3.0 (Internet Explorer) must be disabled."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "EnableSSL3Fallback"
			Value = 0
		}
		@{
			Id    = "DTBI1105-IE11"
			Task  = "Run once selection for running outdated ActiveX controls must be disabled."
			Path  = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext"
			Name  = "RunThisTimeEnabled"
			Value = 0
		}
		@{
			Id    = "DTBI1110-IE11"
			Task  = "Enabling outdated ActiveX controls for Internet Explorer must be blocked."
			Path  = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext"
			Name  = "VersionCheckEnabled"
			Value = 1
		}
		@{
			Id    = "DTBI1115-IE11"
			Task  = "Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Internet Zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "120c"
			Value = 3
		}
		@{
			Id    = "DTBI1120-IE11"
			Task  = "Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Restricted Sites Zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "120c"
			Value = 3
		}
		#This policy setting will only exist on Windows 10 Redstone 2 or later, and is otherwise not applicable.
		@{
			Id    = "DTBI1125-IE11"
			Task  = "VBScript must not be allowed to run in Internet Explorer (Internet zone).(This policy setting will only exist on Windows 10 Redstone 2 or later)"
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "140C"
			Value = 3
		}
		#This policy setting will only exist on Windows 10 Redstone 2 or later, and is otherwise not applicable.
		@{
			Id    = "DTBI1130-IE11"
			Task  = "VBScript must not be allowed to run in Internet Explorer (Restricted Sites zone).(This policy setting will only exist on Windows 10 Redstone 2 or later)"
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "140C"
			Value = 3
		}
	)
}
