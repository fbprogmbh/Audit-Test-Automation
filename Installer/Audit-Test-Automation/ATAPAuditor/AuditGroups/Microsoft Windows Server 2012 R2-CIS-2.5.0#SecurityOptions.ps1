[AuditTest] @{
    Id = "2.3.1.1"
    Task = "(L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled' (MS only)"
    Test = {
        secedit /export /cfg c:\temp\secpol.cfg
        $userInfo = Get-Content -Path c:\temp\secpol.cfg
        $administratorAccountStatus = $userInfo[17]
        $guestAccountStatus = $userInfo[18]
        $renameAdministratorAccount = $userInfo[13]
        $renameGuestAccount = $userInfo[14]
        $forceLogoffNetworkSecurity = $userInfo[12]
        
        $USERRIGHT = "HALLO!"
        
        $currentUserRights = $securityPolicy["Privilege Rights"][""]
        
        
        
        if($administratorAccountStatus -eq "EnableAdminAccount = 0"){
            Write-Output "Passt"
        }
        else{
            Write-Output "NENE"
        }
    }
}
[AuditTest] @{
    Id = "2.3.1.3"
    Task = "(L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)"
    Test = {
        secedit /export /cfg c:\temp\secpol.cfg
        $userInfo = Get-Content -Path c:\temp\secpol.cfg
        $administratorAccountStatus = $userInfo[17]
        $guestAccountStatus = $userInfo[18]
        $renameAdministratorAccount = $userInfo[13]
        $renameGuestAccount = $userInfo[14]
        $forceLogoffNetworkSecurity = $userInfo[12]
        
        $USERRIGHT = "HALLO!"
        
        $currentUserRights = $securityPolicy["Privilege Rights"][""]
        
        
        
        if($administratorAccountStatus -eq "EnableAdminAccount = 0"){
            Write-Output "Passt"
        }
        else{
            Write-Output "NENE"
        }
    }
}
[AuditTest] @{
    Id = "2.3.1.5"
    Task = "(L1) Configure 'Accounts: Rename administrator account'"
    Test = {
        secedit /export /cfg c:\temp\secpol.cfg
        $userInfo = Get-Content -Path c:\temp\secpol.cfg
        $administratorAccountStatus = $userInfo[17]
        $guestAccountStatus = $userInfo[18]
        $renameAdministratorAccount = $userInfo[13]
        $renameGuestAccount = $userInfo[14]
        $forceLogoffNetworkSecurity = $userInfo[12]
        
        $USERRIGHT = "HALLO!"
        
        $currentUserRights = $securityPolicy["Privilege Rights"][""]
        
        
        
        if($administratorAccountStatus -eq "EnableAdminAccount = 0"){
            Write-Output "Passt"
        }
        else{
            Write-Output "NENE"
        }
    }
}
[AuditTest] @{
    Id = "2.3.1.6"
    Task = "(L1) Configure 'Accounts: Rename guest account'"
    Test = {
        secedit /export /cfg c:\temp\secpol.cfg
        $userInfo = Get-Content -Path c:\temp\secpol.cfg
        $administratorAccountStatus = $userInfo[17]
        $guestAccountStatus = $userInfo[18]
        $renameAdministratorAccount = $userInfo[13]
        $renameGuestAccount = $userInfo[14]
        $forceLogoffNetworkSecurity = $userInfo[12]
        
        $USERRIGHT = "HALLO!"
        
        $currentUserRights = $securityPolicy["Privilege Rights"][""]
        
        
        
        if($administratorAccountStatus -eq "EnableAdminAccount = 0"){
            Write-Output "Passt"
        }
        else{
            Write-Output "NENE"
        }
    }
}
[AuditTest] @{
    Id = "2.3.11.6"
    Task = "(L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
    Test = {
        secedit /export /cfg c:\temp\secpol.cfg
        $userInfo = Get-Content -Path c:\temp\secpol.cfg
        $administratorAccountStatus = $userInfo[17]
        $guestAccountStatus = $userInfo[18]
        $renameAdministratorAccount = $userInfo[13]
        $renameGuestAccount = $userInfo[14]
        $forceLogoffNetworkSecurity = $userInfo[12]
        
        $USERRIGHT = "HALLO!"
        
        $currentUserRights = $securityPolicy["Privilege Rights"][""]
        
        
        
        if($administratorAccountStatus -eq "EnableAdminAccount = 0"){
            Write-Output "Passt"
        }
        else{
            Write-Output "NENE"
        }
    }
}
