# Requirements for Mozilla FireFox DISA STIG V4R24

@{
	# RegistrySettings = @(
	# 	@{
	# 		Id    = "DTBF003"
	# 		Task  = "Installed version of Firefox unsupported."
	# 		Path  = "HKLM\Software\Mozilla\Mozilla Firefox\CurrentVersion"
	# 		Name  = "firefox.exe"
	# 		Value = 0 # is equal to or greater than 50.1.x (or ESR 45.7.x)
	# 	}
	# )
	FirefoxLockPrefSettings = @(
		@{
			Id   = "DTBF030"
			Task = "Firewall traversal from remote host must be disabled."
			LockPrefs = @(
				@{ Name  = "security.enable_tls"; Value = $true }
				@{ Name  = "security.tls.version.min"; Value = 2 }
				@{ Name  = "security.tls.version.max"; Value = 3 }
			)
		}
		@{
			Id   = "DTBF050"
			Task = "FireFox is configured to ask which certificate to present to a web site when a certificate is required."
			LockPrefs = @(
				@{ Name  = "security.default_personal_cert"; Value = "Ask Every Time" }
			)
		}
		# @{ # Not set - in CIS Benchmarks
		# 	Id = "DTBF080"
		# 	Task = "Firefox application is set to auto-update."
		# }
		@{
			Id   = "DTBF085"
			Task = "Firefox automatically checks for updated version of installed Search plugins."
			LockPrefs = @(
				@{ Name  = "browser.search.update"; Value = $false }
			)
		}
		@{
			Id   = "DTBF090"
			Task = "Firefox automatically updates installed add-ons and plugins."
			LockPrefs = @(
				@{ Name  = "extensions.update.enabled"; Value = $false }
			)
		}
		@{
			Id   = "DTBF105"
			Task = "Network shell protocol is enabled in FireFox."
			LockPrefs = @(
				@{ Name  = "network.protocol-handler.external.shell"; Value = $false }
			)
		}
		# @{ # no longer available 
		# 	Id = "DTBF110"
		# 	Task = "Firefox is not configured to prompt a user before downloading and opening required file types."
		# }
		# @{ # no longer available 
		# 	Id = "DTBF130"
		# 	Task = "Firefox is not configured to provide warnings when a user switches from a secure (SSL-enabled) to a non-secure page."
		# }
		@{
			Id   = "DTBF140"
			Task = "Firefox formfill assistance option is disabled."
			LockPrefs = @(
				@{ Name  = "browser.formfill.enable"; Value = $false }
			)
		}
		@{
			Id   = "DTBF150"
			Task = "Firefox is configured to autofill passwords."
			LockPrefs = @(
				@{ Name  = "signon.autofillForms"; Value = $false }
			)
		}
		# @{ # Not set - in CIS Benchmarks
		# 	Id = "DTBF160"
		# 	Task = "FireFox is configured to use a password store with or without a master password."
		# }
		# @{ # Not set - see CIS benchmark 5.4_L1_Disallow_JavaScripts_Ability_to_Hide_the_Status_Bar
		# 	Id = "DTBF180"
		# 	Task = "FireFox is not configured to block pop-up windows.
		# }
		@{
			Id   = "DTBF181"
			Task = "FireFox is configured to allow JavaScript to move or resize windows."
			LockPrefs = @(
				@{ Name  = "dom.disable_window_move_resize"; Value = $true }
			)
		}
		@{
			Id   = "DTBF183"
			Task = " Firefox is configured to allow JavaScript to disable or replace context menus."
			LockPrefs = @(
				@{ Name  = "dom.event.contextmenu.enabled"; Value = $false }
			)
		}
		# @{ # Not set - in CIS Benchmarks
		# 	Id = "DTBF184"
		# 	Task = "Firefox is configured to allow JavaScript to hide or change the status bar."
		# }
		# @{ # no longer available 
		# 	Id = "DTBF186"
		# 	Task = "Extensions install must be disabled."
		# }
		@{
			Id   = "DTBF190"
			Task = "Background submission of information to Mozilla must be disabled."
			LockPrefs = @(
				@{ Name  = "datareporting.policy.dataSubmissionEnabled"; Value = $false }
				@{ Name  = "datareporting.healthreport.service.enabled"; Value = $false }
				@{ Name  = "datareporting.healthreport.uploadEnabled"; Value = $false }
			)
		}
	)
}
