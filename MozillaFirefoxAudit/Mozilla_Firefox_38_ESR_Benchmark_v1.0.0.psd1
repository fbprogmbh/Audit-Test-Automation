# Mozilla Firefox 38 ESR Benchmark v1.0.0

@{
	FirefoxLockPrefSettings = @(
		@{
			Id   = "2.1"
			Task = "Enable Automatic Updates"
			LockPrefs = @(
				@{ Name = "app.update.auto"; Value = $true }
				@{ Name = "app.update.enabled"; Value = $true }
				@{ Name = "app.update.staging.enabled"; Value = $true }
			)
		}
		@{
			Id   = "2.2"
			Task = "Enable Auto-Notification of Outdated Plugins"
			LockPrefs = @(
				@{ Name = "plugins.update.notifyUser"; Value = $true }
			)
		}
		@{
			Id   = "2.3"
			Task = "Enable Information Bar for Outdated Plugins"
			LockPrefs = @(
				@{ Name = "plugins.hide_infobar_for_outdated_plugin"; Value = $false }
			)
		}
		@{
			Id   = "2.4"
			Task = "Set Update Interval Time Checks"
			LockPrefs = @(
				@{ Name = "app.update.interval"; Value = 43200 }
			)
		}
		@{
			Id   = "2.5"
			Task = "Set Update Wait Time Prompt"
			LockPrefs = @(
				@{ Name = "app.update.promptWaitTime"; Value = 172800 }
			)
		}
		@{
			Id   = "2.6"
			Task = "Ensure Update-related UI Components are Displayed"
			LockPrefs = @(
				@{ Name = "app.update.silent"; Value = $false }
			)
		}
		@{
			Id   = "2.7"
			Task = "Set Search Provider Update Behavior"
			LockPrefs = @(
				@{ Name = "app.update.auto"; Value = $true }
				@{ Name = "app.update.enabled"; Value = $true }
			)
		}
		# @{
		# 	Id   = "3.1"
		# 	Task = "Validate Proxy Settings"
		# }
		@{
			Id   = "3.2"
			Task = "Do Not Send Cross SSLTLS Referrer Header"
			LockPrefs = @(
				@{ Name = "network.http.sendSecureXSiteReferrer"; Value = $false }
			)
		}
		@{
			Id   = "3.3"
			Task = "Disable NTLM v1"
			LockPrefs = @(
				@{ Name = "network.auth.force-generic-ntlm-v1"; Value = $false }
			)
		}
		@{
			Id   = "3.4"
			Task = "Enable Warning For Phishy URLs"
			LockPrefs = @(
				@{ Name = "network.http.phishy-userpass-length"; Value = 1 }
			)
		}
		@{
			Id   = "3.5"
			Task = "Enable IDN Show Punycode"
			LockPrefs = @(
				@{ Name = "network.IDN_show_punycode"; Value = $true }
			)
		}
		@{
			Id   = "3.6"
			Task = "Set File URI Origin Policy"
			LockPrefs = @(
				@{ Name = "security.fileuri.strict_origin_policy"; Value = $true }
			)
		}
		@{
			Id   = "3.7"
			Task = "Disable Cloud Sync"
			LockPrefs = @(
				@{ Name = "services.sync.enabled"; Value = $false }
			)
		}
		@{
			Id   = "3.8"
			Task = "Disable WebRTC"
			LockPrefs = @(
				@{ Name = "media.peerconnection.enabled"; Value = $false }
				@{ Name = "media.peerconnection.use_document_iceservers"; Value = $false }
			)
		}
		@{
			Id   = "4.1"
			Task = "Set SSL Override Behavior"
			LockPrefs = @(
				@{ Name  = "browser.ssl_override_behavior"; Value = 0 }
			)
		}
		@{
			Id   = "4.2"
			Task = "Set Security TLS Version Maximum"
			LockPrefs = @(
				@{ Name  = "security.tls.version.max"; Value = 3 }
			)
		}
		@{
			Id   = "4.3"
			Task = "Set Security TLS Version Minimum "
			LockPrefs = @(
				@{ Name  = "security.tls.version.min"; Value = 1 }
			)
		}
		@{
			Id   = "4.4"
			Task = "Set OCSP Use Policy"
			LockPrefs = @(
				@{ Name  = "security.OCSP.enabled"; Value = 1 }
			)
		}
		@{
			Id   = "4.5"
			Task = "Block Mixed Active Content"
			LockPrefs = @(
				@{ Name  = "security.mixed_content.block_active_content"; Value = $true }
			)
		}
		@{
			Id   = "4.6"
			Task = "Set OCSP Response Policy"
			LockPrefs = @(
				@{ Name  = "security.OCSP.require"; Value = $true }
			)
		}
		@{
			Id   = "5.1"
			Task = "Disallow JavaScripts Ability to Change the Status Bar Text"
			LockPrefs = @(
				@{ Name = "dom.disable_window_status_change"; Value = $true }
			)
		}
		@{
			Id   = "5.2"
			Task = "Disable Scripting of Plugins by JavaScript"
			LockPrefs = @(
				@{ Name = "security.xpconnect.plugin.unrestricted"; Value = $false }
			)
		}
		@{
			Id   = "5.3"
			Task = "Disallow JavaScripts Ability to Hide the Address Bar"
			LockPrefs = @(
				@{ Name = "dom.disable_window_open_feature.location"; Value = $true }
			)
		}
		@{
			Id   = "5.4"
			Task = "Disallow JavaScripts Ability to Hide the Status Bar"
			LockPrefs = @(
				@{ Name = "dom.disable_window_open_feature.status"; Value = $true }
			)
		}
		@{
			Id   = "5.5"
			Task = "Disable Closing of Windows via Scripts"
			LockPrefs = @(
				@{ Name = "dom.allow_scripts_to_close_windows"; Value = $false }
			)
		}
		@{
			Id   = "5.6"
			Task = "Block Pop-up Windows"
			LockPrefs = @(
				@{ Name = "privacy.popups.policy"; Value = 1 }
			)
		}
		@{
			Id   = "5.7"
			Task = "Disable Displaying JavaScript in History URLs"
			LockPrefs = @(
				@{ Name = "browser.urlbar.filter.javascript"; Value = $true }
			)
		}
		@{
			Id   = "6.1"
			Task = "Disallow Credential Storage"
			LockPrefs = @(
				@{ Name = "signon.rememberSignons"; Value = $false }
			)
		}
		@{
			Id   = "6.2"
			Task = "Do Not Accept Third Party Cookies"
			LockPrefs = @(
				@{ Name = "network.cookie.cookieBehavior"; Value = 1 }
			)
		}
		@{
			Id   = "6.3"
			Task = "Tracking Protection"
			LockPrefs = @(
				@{ Name = "privacy.donottrackheader.enabled"; Value = $true }
				@{ Name = "privacy.donottrackheader.value"; Value = 1 }
				@{ Name = "privacy.trackingprotection.enabled"; Value = $true }
				@{ Name = "privacy.trackingprotection.pbmode"; Value = $true }
			)
		}
		@{
			Id   = "6.4"
			Task = "Set Delay for Enabling Security Sensitive Dialog Boxes"
			LockPrefs = @(
				@{ Name = "security.dialog_enable_delay"; Value = 2000 }
			)
		}
		@{
			Id   = "6.5"
			Task = "Disable Geolocation Serivces"
			LockPrefs = @(
				@{ Name = "geo.enabled"; Value = $false }
			)
		}
		@{
			Id   = "7.1"
			Task = "Secure Application Plug-ins"
			LockPrefs = @(
				@{ Name = "browser.helperApps.alwaysAsk.force"; Value = $true }
			)
		}
		@{
			Id   = "7.2"
			Task = "Disabling Auto-Install of Add-ons"
			LockPrefs = @(
				@{ Name = "xpinstall.whitelist.required"; Value = $true }
			)
		}
		@{
			Id   = "7.3"
			Task = "Enable Extension Block List"
			LockPrefs = @(
				@{ Name = "extensions.blocklist.enabled"; Value = $true }
			)
		}
		@{
			Id   = "7.4"
			Task = "Set Extension Block List Interval"
			LockPrefs = @(
				@{ Name = "extensions.blocklist.interval"; Value = 86400 }
			)
		}
		@{
			Id   = "7.5"
			Task = "Enable Warning for External Protocol Handler"
			LockPrefs = @(
				@{ Name = "network.protocol-handler.warn-external-default"; Value = $true }
			)
		}
		@{
			Id   = "7.6"
			Task = "Disable Popups Initiated by Plugins"
			LockPrefs = @(
				@{ Name = "privacy.popups.disable_from_plugins"; Value = 2 }
			)
		}
		@{
			Id   = "7.7"
			Task = "Enable Extension Auto Update"
			LockPrefs = @(
				@{ Name = "extensions.update.autoUpdateDefault"; Value = $true }
			)
		}
		@{
			Id   = "7.8"
			Task = "Enable Extension Update"
			LockPrefs = @(
				@{ Name = "extensions.update.enabled"; Value = $true }
			)
		}
		@{
			Id   = "7.9"
			Task = "Set Extension Update Interval Time Checks"
			LockPrefs = @(
				@{ Name = "extensions.update.interval"; Value = 86400 }
			)
		}
		@{
			Id   = "8.1"
			Task = "Enable Virus Scanning for Downloads"
			LockPrefs = @(
				@{ Name = "browser.download.manager.scanWhenDone"; Value = $true }
			)
		}
		@{
			Id   = "8.2"
			Task = "Disable JAR from Opening Unsafe File Types"
			LockPrefs = @(
				@{ Name = "network.jar.open-unsafe-types"; Value = $false }
			)
		}
		@{
			Id   = "8.3"
			Task = "Block Reported Web Forgeries"
			LockPrefs = @(
				@{ Name = "browser.safebrowsing.enabled"; Value = $true }
			)
		}
		@{
			Id   = "8.4"
			Task = "Block Reported Attack Sites"
			LockPrefs = @(
				@{ Name = "browser.safebrowsing.malware.enabled"; Value = $true }
			)
		}
	)
}
