[AuditTest] @{
    Id = "2.1.1"
    Task = "Enable Automatic Updates"
    Test = {
        $currentLockPrefs = (Get-AuditResource 'FirefoxPreferences').LockedPreferences
        $preferenceConfigPath = (Get-AuditResource 'FirefoxPreferences').PreferenceConfigPath
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
        if (-not (Test-Path $preferenceConfigPath) -or $null -eq $currentLockPrefs) {
            return @{
                Status = "False"
                Message = 'Could not get general config.'
            }
        }
        
        $missingLockPrefs = @()
        foreach ($preference in $Preferences) {
            if ($preference -notin $currentLockPrefs) {
                $missingLockPrefs +=$preference
            }
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
