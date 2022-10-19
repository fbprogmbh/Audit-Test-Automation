<#
.SYNOPSIS
	Get a firewall setting.
.DESCRIPTION
	A resource provides abstration over an existing system resource. It is used by AuditTests.
.PARAMETER Name
	The name of the resource.
.EXAMPLE
	PS C:\> Get-AuditResource -Name "WindowsSecurityPolicy"
	Gets the WindowsSecurityPolicy resource.
#>
function Get-FirewallSetting {
    param (
        [String]$Name,
        [String]$Setting
    )
    return (Get-NetFirewallProfile -Name $Name).$Setting;
}

<#
.SYNOPSIS
	Check if at least one of two paths have correct key
.DESCRIPTION
	A resource provides abstration over an existing system resource. It is used by AuditTests.
.PARAMETER Name
    Two registry paths, key and expected value

.EXAMPLE
	PS C:\> Get-AuditResource -Name "WindowsSecurityPolicy"
	Gets the WindowsSecurityPolicy resource.
#>
function CheckTwoPaths {
    param (
        $path1,
        $path2,
        $key,
        $expectedValue
    )
    $regValue = $null
    #check if first path exists
    if (Test-Path $path1) {
        #check if value is set correctly
        $regValue = Get-ItemProperty -Path $path1 -Name $key -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "$($key)"
        #if regValue is null
        if ($null -eq $regValue) {
            #check second path
            if (Test-Path $path2) {
                #check if value is set correctly
                $regValue = Get-ItemProperty -Path $path2 -Name $key -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "$($key)"
                #if both paths don't have specific key
                if ($null -eq $regValue) {
                    return @{
                        Message = "Registry key not found."
                        Status  = "False"
                    }
                }
            }
        }
        else {
            #check first path if key is set correctly (if key is found)
            if ($regValue -eq $expectedValue) {
                ## correctly set
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            else {
                #check second path
                if (Test-Path $path2) {
                    #check if value is set correctly
                    $regValue = Get-ItemProperty -Path $path2 -Name $key -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "$($key)"
                    #if both paths don't have specific key
                    if ($null -eq $regValue) {
                        return @{
                            Message = "Registry key not found."
                            Status  = "False"
                        }
                    }
                    else {
                        if ($regValue -eq $expectedValue) {
                            ## correctly set
                            return @{
                                Message = "Compliant"
                                Status  = "True"
                            }
                        }
                        #Go here if both rules are not set correctly
                        else {
                            return @{
                                Message = "Registry value is '$regValue'. Expected: $($expectedValue)"
                                Status  = "False"
                            }
                        }
                                    
                    }
                }
            }
        }
    }
    elseif (Test-Path $path2) {
        #check if value is set correctly
        $regValue = Get-ItemProperty -Path $path2 -Name $key -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "$($key)"
        #if both paths don't have specific key
        if ($null -eq $regValue) {
            return @{
                Message = "Registry key not found."
                Status  = "False"
            }
        }
        else {
            if ($regValue -eq $expectedValue) {
                ## correctly set
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            #Go here if both rules are not set correctly
            else {
                return @{
                    Message = "Registry value is '$regValue'. Expected: $($expectedValue)"
                    Status  = "False"
                }
            }           
        }
    }
    return @{
        Message = "Registry key not found."
        Status  = "False"
    }
}