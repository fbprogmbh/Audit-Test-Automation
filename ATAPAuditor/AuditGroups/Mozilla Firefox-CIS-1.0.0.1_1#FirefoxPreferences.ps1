[AuditTest] @{
    Id = "2.1.1"
    Task = "Enable Automatic Updates"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "app.update.auto"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "2.1.2"
    Task = "Enable Automatic Updates"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "app.update.enabled"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "2.1.3"
    Task = "Enable Automatic Updates"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "app.update.staging.enabled"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "2.2"
    Task = "Enable Auto-Notification of Outdated Plugins"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "plugins.update.notifyUser"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "2.3"
    Task = "Enable Information Bar for Outdated Plugins"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "plugins.hide_infobar_for_outdated_plugin"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "2.4"
    Task = "Set Update Interval Time Checks"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "app.update.interval"; Value = 43200
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "2.5"
    Task = "Set Update Wait Time Prompt"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "app.update.promptWaitTime"; Value = 172800
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "2.6"
    Task = "Ensure Update-related UI Components are Displayed"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "app.update.silent"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "2.7"
    Task = "Set Search Provider Update Behavior"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "browser.search.update"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.1"
    Task = "Validate Proxy Settings"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "network.proxy.type"; Value = 5
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.2"
    Task = "Do Not Send Cross SSL/TLS Referrer Header"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "network.http.sendSecureXSiteReferrer"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.3"
    Task = "Disable Sending LM Hash"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "network.auth.force-generic-ntlm-v1"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.4"
    Task = "Enable Warning For `"Phishy`" URLs"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "network.http.phishy-userpass-length"; Value = 1
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.5"
    Task = "Enable IDN Show Punycode"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "network.IDN_show_punycode"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.6"
    Task = "Disable JAR from opening Unsafe File Types"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "security.fileuri.strict_origin_policy"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.7"
    Task = "Set File URI Origin Policy"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "services.sync.enabled"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.8.1"
    Task = "Disable WebRTC"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "media.peerconnection.enabled"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "3.8.2"
    Task = "Disable WebRTC"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "media.peerconnection.use_document_iceservers"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "4.1"
    Task = "Set SSL Override Behavior"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "browser.ssl_override_behavior"; Value = 0
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "4.2"
    Task = "Set Security TLS Version Maximum"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "security.tls.version.max"; Value = 3
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "4.3"
    Task = "Set Security TLS Version Minimum "
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "security.tls.version.min"; Value = 1
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "4.4"
    Task = "Set OCSP Use Policy"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "security.OCSP.enabled"; Value = 1
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "4.5"
    Task = "Block Mixed Active Content"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "security.mixed_content.block_active_content"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "4.6"
    Task = "Set OCSP Response Policy"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "security.OCSP.require"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "5.1"
    Task = "Disallow JavaScript's Ability to Change the Status Bar Text"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "dom.disable_window_status_change"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "5.2"
    Task = "Disable Scripting of Plugins by JavaScript"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "security.xpconnect.plugin.unrestricted"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "5.3"
    Task = "Disallow JavaScript's Ability to Hide the Address Bar"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "dom.disable_window_open_feature.location"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "5.4"
    Task = "Disallow JavaScript's Ability to Hide the Status Bar"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "dom.disable_window_open_feature.status"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "5.5"
    Task = "Disable Closing of Windows via Scripts"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "dom.allow_scripts_to_close_windows"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "5.6"
    Task = "Block Pop-up Windows"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "privacy.popups.policy"; Value = 1
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "5.7"
    Task = "Disable Displaying JavaScript in History URLs"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "browser.urlbar.filter.javascript"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "6.1"
    Task = "Disallow Credential Storage"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "signon.rememberSignons"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "6.2"
    Task = "Do Not Accept Third Party Cookies"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "network.cookie.cookieBehavior"; Value = 1
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "6.3.1"
    Task = "Send Do Not Track Header"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "privacy.donottrackheader.enabled"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "6.3.2"
    Task = "Send Do Not Track Header value"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "privacy.donottrackheader.value"; Value = 1
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "6.3.3"
    Task = "Tracking Protection"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "privacy.trackingprotection.enabled"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "6.3.4"
    Task = "Tracking Protection mode"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "privacy.trackingprotection.pbmode"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "6.4"
    Task = "Set Delay for Enabling Security Sensitive Dialog Boxes"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "security.dialog_enable_delay"; Value = 2000
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.1"
    Task = "Secure Application Plug-ins"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "browser.helperApps.alwaysAsk.force"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.2"
    Task = "Disabling Auto-Install of Add-ons"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "xpinstall.whitelist.required"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.3"
    Task = "Enable Extension Block List"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "extensions.blocklist.enabled"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.4"
    Task = "Set Extension Block List Interval"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "extensions.blocklist.interval"; Value = 86400
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.5"
    Task = "Enable Warning for External Protocol Handler"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "network.protocol-handler.warn-external-default"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.6"
    Task = "Disable Popups Initiated by Plugins"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "privacy.popups.disable_from_plugins"; Value = 2
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.7"
    Task = "Enable Extension Auto Update"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "extensions.update.autoUpdateDefault"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.8"
    Task = "Enable Extension Update"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "extensions.update.enabled"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "7.9"
    Task = "Set Extension Update Interval Time Checks"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "extensions.update.interval"; Value = 86400
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "8.1"
    Task = "Enable Virus Scanning for Downloads"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "browser.download.manager.scanWhenDone"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "8.2"
    Task = "Block Reported Web Forgeries"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "network.jar.open-unsafe-types"; Value = $false
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "8.3"
    Task = "Block Reported Attack Sites"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "browser.safebrowsing.enabled"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
[AuditTest] @{
    Id = "8.4"
    Task = "Block Reported Attack Sites"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        $preference = @{ Name = "browser.safebrowsing.malware.enabled"; Value = $true
        }
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = $preference | Where-Object {
        			$preference = $_
        			# LockPref not in currentLockPrefs
        			($currentLockPrefs | Where-Object {
        				($_.Name -eq $preference.Name) -and ($_.Value -is $preference.Value.GetType()) -and ($_.Value -eq $preference.Value)
        			}).Count -eq 0
        		}
        
        if ($missingLockPrefs.Count -gt 0) {
            $msg = ($missingLockPrefs | ForEach-Object { "lockPref(`"{0}`", {1})" -f $_.Name, $_.Value }) -join "; "
        
            return @{
                Status = "False"
                Message = "Missing lockprefs: $msg."
            }
        }
        
        return @{
            Status = "True"
            Message = "Compliant."
        }
    }
}
