# Requirements for Google Chrome DISA STIG V1R15 

@{
	RegistrySettings = @(
		@{
			Id    = "DTBC-0001"
			Task  = "Firewall traversal from remote host must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "RemoteAccessHostFirewallTraversal"
			Value = 0
		}
		@{
			Id    = "DTBC-0003"
			Task  = "Sites ability for showing desktop notifications must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DefaultNotificationsSetting"
			Value = 2
		}
		@{
			Id    = "DTBC-0004"
			Task  = "Sites ability to show pop-ups must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DefaultPopupsSetting"
			Value = 2
		}
		@{
			Id    = "DTBC-0002"
			Task  = "Site tracking users location must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DefaultGeolocationSetting"
			Value = 2
		}
		@{
			Id    = "DTBC-0005"
			Task  = "Extensions installation must be blacklisted by default."
			Path  = "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlacklist"
			Name  = "1"
			Value = "*"
		}
		@{
			Id    = "DTBC-0006"
			Task  = "Extensions that are approved for use must be whitelisted."
			Path  = "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist"
			Name  = "ExtensionInstallWhitelist"
			Value = 1 
		}<#
		@{
			Id    = "DTBC-0007"
			Task  = "The default search providers name must be set."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DefaultSearchProviderName"
			Value = 
		}
		@{
			Id    = "DTBC-0008"
			Task  = "The default search provider URL must be set to perform encrypted searches."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DefaultSearchProviderSearchURL"
			Value = an organization-approved encrypted search string (ex. https://www.google.com/#q={searchTerms} or https://www.bing.com/search?q={searchTerms} ) this is a finding.
		}#>
        #Note: This policy will only display in the chrome://policy tab on domain joined systems. On standalone systems, the policy will not display.
		@{
			Id    = "DTBC-0009"
			Task  = "Default search provider must be enabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DefaultSearchProviderEnabled"
			Value = 1
		}
		@{
			Id    = "DTBC-0011"
			Task  = "The Password Manager must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "PasswordManagerEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0013"
			Task  = "The running of outdated plugins must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome"
			Name  = "AllowOutdatedPlugins"
			Value = 0
		}
		@{
			Id    = "DTBC-0015"
			Task  = "Third party cookies must be blocked."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "BlockThirdPartyCookies"
			Value = 1
		}
		@{
			Id    = "DTBC-0017"
			Task  = "Background processing must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "BackgroundModeEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0019"
			Task  = "3D Graphics APIs must be disabled. (Note: If 3D APIs are required by mission, this is not a finding.)"
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "Disable3DAPIs"
			Value = 1
		}
		@{
			Id    = "DTBC-0020"
			Task  = "Google Data Synchronization must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "SyncDisabled"
			Value = 1
		}<#
		@{
			Id    = "DTBC-0021"
			Task  = "The URL protocol schema javascript must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\URLBlacklist"
			Name  = "URLBlacklist key"
			Value = javascript://* under the Policy Value column

Windows method:
   1. Start regedit
   2. Navigate to HKLM\Software\Policies\Google\Chrome\URLBlacklist
   3. If the URLBlacklist key does not exist, or the does not contain entries 1 set to javascript://*,  then this is a finding.
		}#>
		@{
			Id    = "DTBC-0023"
			Task  = "Cloud print sharing must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "CloudPrintProxyEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0025"
			Task  = "Network prediction must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "NetworkPredictionOptions"
			Value = 2
		}
		@{
			Id    = "DTBC-0026"
			Task  = "Metrics reporting to Google must be disabled. (Note: This policy will only display in the chrome://policy tab on domain joined systems. On standalone systems, the policy will not display.)"
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "MetricsReportingEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0027"
			Task  = "Search suggestions must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "SearchSuggestEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0029"
			Task  = "Importing of saved passwords must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "ImportSavedPasswords"
			Value = 0
		}
		@{
			Id    = "DTBC-0030"
			Task  = "Incognito mode must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "IncognitoModeAvailability"
			Value = 1
		}
		@{
			Id    = "DTBC-0037"
			Task  = "Online revocation checks must be done."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "EnableOnlineRevocationChecks"
			Value = 1
		}
		@{
			Id    = "DTBC-0038"
			Task  = "Safe Browsing must be enabled,"
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "SafeBrowsingEnabled"
			Value = 1
		}
		@{
			Id    = "DTBC-0039"
			Task  = "Browser history must be saved."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "SavingBrowserHistoryDisabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0040"
			Task  = "Default behavior must block webpages from automatically running plugins."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DefaultPluginsSetting"
			Value = 3
		}<#
		@{
			Id    = "DTBC-0045"
			Task  = "Session only based cookies must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls"
			Name  = ""
			Value = 
		}#>
		@{
			Id    = "DTBC-0051"
			Task  = "URLs must be whitelisted for plugin use"
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "PluginsAllowedForUrls"
			Value = "Suggested: the set or subset of [*.]mil and [*.]gov"
		}
		@{
			Id    = "DTBC-0052"
			Task  = "Deletion of browser history must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "AllowDeletingBrowserHistory"
			Value = 0
		}
		@{
			Id    = "DTBC-0053"
			Task  = "Prompt for download location must be enabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "PromptForDownloadLocation"
			Value = 1
		}<#
		@{
			Id    = "DTBC-0055"
			Task  = "Download restrictions must be configured."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DownloadRestrictions"
			Value = 1" or "2"
		}#>
		@{
			Id    = "DTBC-0064"
			Task  = "Autoplay must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "AutoplayAllowed"
			Value = 0
		}
		@{
			Id    = "DTBC-0056"
			Task  = "Chrome must be configured to allow only TLS."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "SSLVersionMin"
			Value = "tls1.1"
		}
		@{
			Id    = "DTBC-0057"
			Task  = "Safe Browsing Extended Reporting must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "SafeBrowsingExtendedReportingEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0058"
			Task  = "WebUSB must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "DefaultWebUsbGuardSetting"
			Value = 2
		}<#
		@{
			Id    = "DTBC-0065"
			Task  = "URLs must be whitelisted for Autoplay use."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "AutoplayWhitelist"
			Value = Suggested: the set or subset of [*.]mil and [*.]gov
		}#>
		@{
			Id    = "DTBC-0060"
			Task  = "Chrome Cleanup must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "ChromeCleanupEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0061"
			Task  = "Chrome Cleanup reporting must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "ChromeCleanupReportingEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0063"
			Task  = "Google Cast must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "EnableMediaRouter"
			Value = 0
		}
		@{
			Id    = "DTBC-0066"
			Task  = "Anonymized data collection must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "UrlKeyedAnonymizedDataCollectionEnabled"
			Value = 0
		}
		@{
			Id    = "DTBC-0067"
			Task  = "Collection of WebRTC event logs must be disabled."
			Path  = "HKLM:\Software\Policies\Google\Chrome\"
			Name  = "WebRtcEventLogCollectionAllowed"
			Value = 0
		}
	)
}
