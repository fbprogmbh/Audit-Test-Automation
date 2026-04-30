. "$RootPath\Helpers\LinuxHelper.ps1"

$rcFirewallStatus1 = "Using nftables"
$rcFirewallStatus2 = "Using ufw"
$rcFirewallStatus3 = "Using iptables"

$retCompliant = @{
    Message = $rcCompliant
    Status = $rcTrue
}
$retNonCompliant = @{
    Message = $rcNonCompliant
    Status = $rcFalse
}
$retCompliantIPv6Disabled = @{
    Message = $rcCompliantIPv6isDisabled
    Status = $rcTrue
}
$retNonCompliantManualReviewRequired = @{
    Message = $rcNonCompliantManualReviewRequired
    Status = $rcNone
}
$retUsingFW1 = @{
    Message = $rcFirewallStatus1
    Status = $rcNone
}
$retUsingFW2 = @{
    Message = $rcFirewallStatus2
    Status = $rcNone
}
$retUsingFW3 = @{
    Message = $rcFirewallStatus3
    Status = $rcNone
}

# Firewall evaluation
function GetFirewallStatus {
    # 0 - undefined
	# 1 - using nftables
	# 2 - using ufw
	# 3 - using iptables

	$t_UFW = Test-PackageInstalled -PackageName ufw
	$t_NFT = Test-PackageInstalled -PackageName nftables
	$t_IPT = Test-PackageInstalled -PackageName iptables
	$t_UFW_en = systemctl is-enabled ufw 2>/dev/null
	if ($t_UFW){
        $t_UFW_inac = /usr/sbin/ufw status 2>/dev/null | grep -iE "Status: Ina[ck]tive?"
        $t_UFW_ac = /usr/sbin/ufw status 2>/dev/null | grep -iE "Status: A[ck]tive?"
    } else {
        $t_UFW_ac = $null
        $t_UFW_inac = $null
    }
	$t_NFT_en = systemctl is-enabled nftables.service 2>/dev/null
	
	# Testing 1 - nftable installed, ufw not or inactive
	if ($t_NFT -and ! $t_IPT -and (! $t_UFW -or $t_UFW_inac -ne $null) -and $t_NFT_en -match "enabled"){
        return 1
    }
	
	# Testing 2 - ufw, iptables installed, nftables not 
	if ( $t_UFW -and $t_UFW_ac -ne $null -and $t_UFW_en -match "enabled" -and $t_IPT -and ! $t_NFT){
        return 2
    }
	
	# Testing 3 - only iptables
	if (! $t_NFT -and ! $t_UFW -and $t_IPT){
        return 3
    }

    return 0
}

$FirewallStatus = GetFirewallStatus

$parentPath = Split-Path -Parent -Path $PSScriptRoot
$scriptPath = $parentPath + "/Helpers/ShellScripts/Ubuntu22.04_Debian12/"
$commonPath = $parentPath + "/Helpers/ShellScripts/common/"

[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure cramfs kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.2"
    Task = "Ensure freevxfs kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.3"
    Task = "Ensure hfs kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.4"
    Task = "Ensure hfsplus kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.5"
    Task = "Ensure jffs2 kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.6"
    Task = "Ensure squashfs kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.7"
    Task = "Ensure udf kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.1.8"
    Task = "Ensure usb-storage kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.1.1"
    Task = "Ensure /tmp is a separate partition"
    Test = {
        $result = findmnt --kernel /tmp
        if($result -match "/tmp"){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.1.2.1.2"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.1.3"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.1.4"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result =  findmnt --kernel /tmp | grep noexec
        if($result -match "noexec"){
            return $retCompliant
        }

        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "1.1.2.2.1"
    Task = "Ensure /dev/shm is a separate partition"
    Test = {
        $script = $scriptPath + "1.1.2.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.2.2.2"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $script = $commonPath + "1.1.2.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.2.3"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $script = $commonPath + "1.1.2.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.2.4"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $script = $commonPath + "1.1.2.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.3.1"
    Task = "Ensure separate partition exists for /home"
    Test = {
        $result = findmnt --kernel /home
        if($result -match "/home"){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.1.2.3.2"
    Task = "Ensure nodev option set on /home partition"
    Test = {
        $script = $commonPath + "1.1.2.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.3.3"
    Task = "Ensure nosuid option set on /home partition"
    Test = {
        $script = $commonPath + "1.1.2.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.4.1"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result = findmnt --kernel /var
        if($result -match !$null){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.1.2.4.2"
    Task = "Ensure nodev option set on /var partition"
    Test = {
        $script = $commonPath + "1.1.2.4.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.4.3"
    Task = "Ensure nosuid option set on /var partition"
    Test = {
        $script = $commonPath + "1.1.2.4.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.5.1"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result = findmnt --kernel /var/tmp
        if($result -match "/var/tmp"){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.1.2.5.2"
    Task = "Ensure nodev option set on /var/tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.5.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.5.3"
    Task = "Ensure nosuid option set on /var/tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.5.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.5.4"
    Task = "Ensure noexec option set on /var/tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.5.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.6.1"
    Task = "Ensure separate partition exists for /var/log"
    Test = {
        $result = findmnt --kernel /var/log
        if($result -match !$null){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.1.2.6.2"
    Task = "Ensure nodev option set on /var/log partition"
    Test = {
        $script = $commonPath + "1.1.2.6.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.6.3"
    Task = "Ensure nosuid option set on /var/log partition"
    Test = {
        $script = $commonPath + "1.1.2.6.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.6.4"
    Task = "Ensure noexec option set on /var/log partition"
    Test = {
        $script = $commonPath + "1.1.2.6.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.7.1"
    Task = "Ensure separate partition exists for /var/log/audit"
    Test = {
        $result = findmnt --kernel /var/log/audit
        if($result -match "/var/log/audit"){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.1.2.7.2"
    Task = "Ensure nodev option set on /var/log/audit partition"
    Test = {
        $script = $commonPath + "1.1.2.7.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.7.3"
    Task = "Ensure nosuid option set on /var/log/audit partition"
    Test = {
        $script = $commonPath + "1.1.2.7.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.1.2.7.4"
    Task = "Ensure noexec option set on /var/log/audit partition"
    Test = {
        $script = $commonPath + "1.1.2.7.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.2.1.1"
    Task = "Ensure GPG keys are configured"
    Test = {
        $result = apt-key list
        if($result -ne $null){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.2.1.2"
    Task = "Ensure package manager repositories are configured"
    Test = {
        $result = apt-cache policy
        if($result -ne $null){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.2.2.1"
    Task = "Ensure updates, patches, and additional security software are installed"
    Test = {
        $output = apt -s upgrade
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.3.1.1"
    Task = "Ensure AppArmor is installed"
    Test = {
        $result = Test-PackageInstalled -PackageName apparmor 2>/dev/null
        if($result){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.3.1.2"
    Task = "Ensure AppArmor is enabled in the bootloader configuration"
    Test = {
        $script = $scriptPath + "1.3.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.3.1.3"
    Task = "Ensure all AppArmor Profiles are in enforce or complain mode"
    Test = {
        $profileMode1 = /usr/sbin/apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = /usr/sbin/apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        $profileMode3 = /usr/sbin/apparmor_status | grep profiles | sed '3!d' | cut -d ' ' -f 1
        $result = expr $profileMode3 + $profileMode2
        
        $unconfinedProcesses = /usr/sbin/apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1

        if($result -eq $profileMode1 -and $unconfinedProcesses -eq 0){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.3.1.4"
    Task = "Ensure all AppArmor Profiles are enforcing"
    Test = {
        $script = $scriptPath + "1.3.1.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.4.1"
    Task = "Ensure bootloader password is set"
    Test = {
        $result1 = grep "^set superusers" /boot/grub/grub.cfg
        $result2 = grep "^password" /boot/grub/grub.cfg
        if($result1 -match "set superusers=" -and $result2 -match "password_pbkdf2"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.4.2"
    Task = "Ensure access to bootloader config is configured"
    Test = {
        $script = $commonPath + "1.4.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.5.1"
    Task = "Ensure address space layout randomization is enabled"
    Test = {
        $script = $commonPath + "1.5.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.5.2"
    Task = "Ensure ptrace_scope is restricted"
    Test = {
        $script = $commonPath + "1.5.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id = "1.5.3"
    Task = "Ensure core dumps are restricted"
    Test = {
        $script = $scriptPath + "1.5.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.5.4"
    Task = "Ensure prelink is not installed"
    Test = {
        $test = Test-PackageInstalled -PackageName prelink
        if(! $test){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "1.5.5"
    Task = "Ensure Automatic Error Reporting is not enabled"
    Test = {
        $result1 = dpkg-query -s apport > /dev/null 2>&1 && grep -Psi -- '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport
        $result2 = systemctl is-active apport.service | grep '^active'
        if($result1 -eq $null -and $result2 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.6.1"
    Task = "Ensure message of the day is configured properly"
    Test = {
        $script = $scriptPath + "1.6.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.6.2"
    Task = "Ensure local login warning banner is configured properly"
    Test = {
        $output1 = cat /etc/issue

	if($output1 -eq $null){
	    return $retCompliant
	}

        $output2 = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
        
        if($output1 -ne $null -and $output2 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.6.3"
    Task = "Ensure remote login warning banner is configured properly"
    Test = {
        $output1 = cat /etc/issue.net

	if($output1 -eq $null){
	    return $retCompliant
	}

        $output2 = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net
        
        if($output1 -ne $null -and $output2 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.6.4"
    Task = "Ensure access to /etc/motd is configured"
    Test = {
        $script = $scriptPath + "1.6.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "1.6.5"
    Task = "Ensure access to /etc/issue is configured"
    Test = {
        $output = stat -c '%#a' /etc/issue | grep -q "0644"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.6.6"
    Task = "Ensure access to /etc/issue.net is configured"
    Test = {
        $output = stat -c '%#a' /etc/issue.net | grep -q "0644"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.1"
    Task = "Ensure GDM is removed"
    Test = {
        $test = Test-PackageInstalled -PackageName gdm3
        if(! $test){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.2"
    Task = "Ensure GDM login banner is configured"
    Test = {
        $path = $scriptPath + "1.8.2.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.3"
    Task = "Ensure GDM disable-user-list option is enabled"
    Test = {
        $path = $scriptPath + "1.8.3.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.4"
    Task = "Ensure GDM screen locks when the user is idle"
    Test = {
        $path = $scriptPath + "1.8.4.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.5"
    Task = "Ensure GDM screen locks cannot be overridden"
    Test = {
        $path = $scriptPath + "1.8.5.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.6"
    Task = "Ensure GDM automatic mounting of removable media is disabled"
    Test = {
        $path = $scriptPath + "1.8.6.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.7"
    Task = "Ensure GDM disabling automatic mounting of removable media is not overridden"
    Test = {
        $path = $scriptPath + "1.8.7.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.8"
    Task = "Ensure GDM autorun-never is enabled"
    Test = {
        $path = $scriptPath + "1.8.8.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.9"
    Task = "Ensure GDM autorun-never is not overridden"
    Test = {
        $path = $scriptPath + "1.8.9.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "1.7.10"
    Task = "Ensure XDCMP is not enabled"
    Test = {
        $script = $scriptPath + "1.7.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "2.1.1"
    Task = "Ensure autofs services are not in use"
    Test = {
        $test = Test-PackageInstalled -PackageName autofs
        if(! $test){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null autofs.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.2"
    Task = "Ensure avahi daemon services are not in use"
    Test = {
        $status = Test-PackageInstalled -PackageName avahi-daemon
        if(! $status){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null avahi-daemon.socket
            if(! $?){
                $test3 = systemctl is-enabled 2>/dev/null avahi-daemon.service
                if(! $?){
                    return $retCompliant
                }
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.3"
    Task = "Ensure dhcp server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName isc-dhcp-server
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null isc-dhcp-server.service
            if(! $?){
                $test2 = systemctl is-enabled 2>/dev/null isc-dhcp-server6.service
                if(! $?){
                    return $retCompliant
                }
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.4"
    Task = "Ensure dns server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName bind9
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null bind9.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.5"
    Task = "Ensure dnsmasq server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName dnsmasq
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null dnsmasq.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.6"
    Task = "Ensure ftp server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName vsftpd
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null vsftpd.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.7"
    Task = "Ensure ldap server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName slapd
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null slapd.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.8"
    Task = "Ensure message access server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName dovecot-imapd
        $test2 = Test-PackageInstalled -PackageName dovecot-pop3d
        if(! $test1 -and ! $test2){
            return $retCompliant
        }
        else{
            $test3 = systemctl is-enabled 2>/dev/null dovecot.socket
            if(! $?){
                $test4 = systemctl is-enabled 2>/dev/null dovecot.service
                if(! $?){
                    return $retCompliant
                }
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.9"
    Task = "Ensure network file system services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName nfs-kernel-server
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null nfs-kernel.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.10"
    Task = "Ensure nis server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName ypserv
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null ypserv.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.11"
    Task = "Ensure print server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName cups
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null cups.service
            if(! $?){
                $test3 = systemctl is-enabled 2>/dev/null cups.socket
                if(! $?){
                    return $retCompliant
                }
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.12"
    Task = "Ensure rpcbind services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName rpcbind
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null rpcbind.service
            if(! $?){
                $test3 = systemctl is-enabled 2>/dev/null rpcbind.socket
                if(! $?){
                    return $retCompliant
                }
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.13"
    Task = "Ensure rsync services are not in use"
    Test = {
        $script = $commonPath + "2.1.13.sh"
        bash $script
        if ($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.14"
    Task = "Ensure samba file server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName samba 2>/dev/null
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null samba.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.15"
    Task = "Ensure snmp services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName snmpd
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null snmpd.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.16"
    Task = "Ensure tftp server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName tftpd-hpa
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null tftpd-hpa.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.17"
    Task = "Ensure web proxy server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName squid
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null squid.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.18"
    Task = "Ensure web server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName apache2
        $test2 = Test-PackageInstalled -PackageName ginx
        if(! $test1 -and ! $test2){
            return $retCompliant
        }
        else{
            $services = 'apache2.service', 'apache2.socket', 'nginx.service', 'nginx.socket'
            $test3 = "disabled"
            foreach ($service in $services){
                $test4 = systemctl is-enabled $service 2>/dev/null
                if($?){
                    $test3 = "enabled"
                }
            }
            if($test3 -match "disabled"){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.19"
    Task = "Ensure xinetd services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName xinetd
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null xinetd.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.20"
    Task = "Ensure X window server services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName xserver-common
        if(! $test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.21"
    Task = "Ensure mail transfer agent is configured for local-only mode"
    Test = {
        $test1 = ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.1.22"
    Task = "Ensure only approved services are listening on a network interface"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "2.2.1"
    Task = "Ensure NIS Client is not installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName nis
        if(! $test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.2.2"
    Task = "Ensure rsh client is not installed"
    Test = {
        $status = Test-PackageInstalled -PackageName rsh-client
        if(! $status){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "2.2.3"
    Task = "Ensure talk client is not installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName talk
        if(! $test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "2.2.4"
    Task = "Ensure telnet client Server is not installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName telnet
        if(! $test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "2.2.5"
    Task = "Ensure ldap client is not installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName lapd-utils
        if(! $test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "2.2.6"
    Task = "Ensure ftp client is not installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName ftp
        if(! $test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "2.3.1.1"
    Task = "Ensure a single time synchronization daemon is in use"
    Test = {
        $path = $scriptPath + "2.1.1.1.sh"
        $result = bash $path
        if($result -match "PASS:"){
            return $retCompliant
        }

        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.3.2.1"
    Task = "Ensure systemd-timesyncd configured with authorized timeserver"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "2.3.2.2"
    Task = "Ensure systemd-timesyncd is enabled and running"
    Test = {
        $test1 = systemctl is-enabled systemd-timesyncd.service
        $time = timedatectl status
        if($test1 -match "enabled" -and $time -ne $null){    
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.3.3.1"
    Task = "Ensure chrony is configured with authorized timeserver"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "2.3.3.2"
    Task = "Ensure chrony is running as user _chrony"
    Test = {
        $script = $scriptPath + "2.3.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "2.3.3.3"
    Task = "Ensure chrony is enabled and running"
    Test = {
        $test1 = $(systemctl is-enabled cron.service 1>/dev/null 2>/dev/null; echo $?)
        $test2 = $(systemctl is-active cron.service 1>/dev/null 2>/dev/null; echo $?)
        if($test1 -and $test2 ){
            return $retCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.1"
    Task = "Ensure cron daemon is enabled and active"
    Test = {
        $test1 = systemctl is-enabled cron
        $test2 = systemctl status cron | grep 'Active: active (running) '
        if($test1 -eq "enabled" -and $test2 -match "running"){
            return $retCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.2"
    Task = "Ensure permissions on /etc/crontab are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/crontab | grep -q "0600"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.3"
    Task = "Ensure permissions on /etc/cron.hourly are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/cron.hourly/ | grep -q 0700
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.4"
    Task = "Ensure permissions on /etc/cron.daily are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/cron.daily/ | grep -q "0700"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.5"
    Task = "Ensure permissions on /etc/cron.weekly are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/cron.weekly/ | grep -q "0700"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.6"
    Task = "Ensure permissions on /etc/cron.monthly are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/cron.monthly/ | grep -q "0700"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.7"
    Task = "Ensure permissions on /etc/cron.d are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/cron.d/ | grep -q "0700"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "2.4.1.8"
    Task = "Ensure crontab is restricted to authorized users"
    Test = {
        $script = $commonPath + "2.4.1.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "2.4.2.1"
    Task = "Ensure at is restricted to authorized users"
    Test = {
        $script = $commonPath + "2.4.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.1.1"
    Task = "Ensure IPv6 status is identified"
    Test = {
        $path = $scriptPath + "3.1.1.sh"
        $result = bash $path
        if($result -match "IPv6 is enabled on the system"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "3.1.2"
    Task = "Ensure wireless interfaces are disabled"
    Test = {
        $script = $commonPath + "3.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.1.3"
    Task = "Ensure bluetooth services are not in use"
    Test = {
        $test1 = Test-PackageInstalled -PackageName bluez
        if(! $test1){
            return $retCompliant
        }
        else{
            $test2 = systemctl is-enabled 2>/dev/null bluetooth.service
            if(! $?){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "3.2.1"
    Task = "Ensure dccp kernel module is not available"
    Test = {
        $script = $commonPath + "3.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.2.2"
    Task = "Ensure tipc kernel module is not available"
    Test = {
        $script = $commonPath + "3.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.2.3"
    Task = "Ensure rds kernel module is not available"
    Test = {
        $script = $commonPath + "3.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.2.4"
    Task = "Ensure sctp kernel module is not available"
    Test = {
        $script = $commonPath + "3.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.1"
    Task = "Ensure ip forwarding is disabled"
    Test = {
        $script = $commonPath + "3.3.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.2"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $script = $commonPath + "3.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.3"
    Task = "Ensure bogus icmp responses are ignored"
    Test = {
        $script = $commonPath + "3.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.4"
    Task = "Ensure broadcast icmp requests are ignored"
    Test = {
        $script = $commonPath + "3.3.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.5"
    Task = "Ensure icmp redirects are not accepted"
    Test = {
        $script = $commonPath + "3.3.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.6"
    Task = "Ensure secure icmp redirects are not accepted"
    Test = {
        $script = $commonPath + "3.3.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.7"
    Task = "Ensure reverse path filtering is enabled"
    Test = {
        $script = $commonPath + "3.3.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.8"
    Task = "Ensure source routed packets are not accepted"
    Test = {
        $script = $commonPath + "3.3.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.9"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $script = $commonPath + "3.3.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.10"
    Task = "Ensure tcp syn cookies is enabled"
    Test = {
        $script = $commonPath + "3.3.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "3.3.11"
    Task = "Ensure ipv6 router advertisements are not accepted"
    Test = {
        $script = $commonPath + "3.3.11.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "4.1.1"
    Task = "Ensure ufw is installed"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName ufw
        if($test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.1.2"
    Task = "Ensure iptables-persistent is not installed with ufw"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName iptables-persistent
        if(! $test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.1.3"
    Task = "Ensure ufw service is enabled"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $test1 = systemctl is-enabled ufw 2>/dev/null
        $test2 = systemctl is-active ufw 2>/dev/null
        if($test1 -match "enabled" -and $test2 -match "active"){
            $test3 = /usr/sbin/ufw status | grep -iE "Status: A[ck]tive?"
            if($test3 -ne $null){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.1.4"
    Task = "Ensure ufw loopback traffic is configured"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName ufw
        if($test1){
            $test2 = /usr/sbin/ufw status verbose | grep -iE "Status: A[ck]tive?"
            if($test2 -eq $null){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.1.5"
    Task = "Ensure ufw outbound connections are configured"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName ufw
        if($test1){
            $test2 = /usr/sbin/ufw status numbered | grep -iE "Status: Ina[ck]tive?"
            if($test2 -eq $null){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.1.6"
    Task = "Ensure ufw firewall rules exist for all open ports"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $path = $scriptPath + "3.5.1.6.sh"
        $result = bash $path
        if($result -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.1.7"
    Task = "Ensure ufw default deny firewall policy"
    Test = {
        $test1 = Test-PackageInstalled -PackageName ufw
        if($test1){
            $test2 = /usr/sbin/ufw status verbose | grep -iE "allow"
            if($test2 -eq $null){
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.2.1"
    Task = "Ensure nftables is installed"
    Test = {
        if ($FirewallStatus -match 2) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName nftables
        if($test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.2.2"
    Task = "Ensure ufw is uninstalled or disabled with nftables"
    Test = {
        if ($FirewallStatus -match 2) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName ufw
        if(! $test1){
            return $retCompliant
        } else {
            $test2 = /usr/sbin/ufw status | grep -iE "Status: Ina[ck]tive?"
            if($test2 -ne $null) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
        Id = "4.2.3"
        Task = "Ensure iptables are flushed with nftables"
        Test = {
            if ($FirewallStatus -match 2) {
                return $retUsingFW1
            }
            if ($FirewallStatus -match 3) {
                return $retUsingFW3
            }
                $script = $scriptPath + "4.2.3.sh"
            $result = bash $script
            if ($?) {
                return $retCompliant
            }
            return $retNonCompliant
        }
}
[AuditTest] @{
    Id = "4.2.4"
    Task = "Ensure a nftables table exists"
    Test = {
        try{
            if ($FirewallStatus -match 2) {
                return $retUsingFW1
            }
            if ($FirewallStatus -match 3) {
                return $retUsingFW3
            }
            $test1 = nft list tables
            if($test1 -match "table"){
                return $retCompliant
            }
            return $retNonCompliant
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.2.5"
    Task = "Ensure nftables base chains exist"
    Test = {
        try{
            if ($FirewallStatus -match 2) {
                return $retUsingFW1
            }
            if ($FirewallStatus -match 3) {
                return $retUsingFW3
            }
            $test1 = nft list ruleset | grep 'hook input'
            $test2 = nft list ruleset | grep 'hook forward'
            $test3 = nft list ruleset | grep 'hook output'
            if($test1 -match "type filter hook input" -and $test2 -match "type filter hook forward" -and $test3 -match "type filter hook output"){
                return $retCompliant
            }
            return $retNonCompliant
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.2.6"
    Task = "Ensure nftables loopback traffic is configured"
    Test = {
        try{
            if ($FirewallStatus -match 2) {
                return $retUsingFW1
            }
            if ($FirewallStatus -match 3) {
                return $retUsingFW3
            }
            if($isIPv6Disabled -ne $true){
                $test1 = nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'
                $test2 = nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'
                if($test1 -match 'iif "lo" accept' -and $test2 -match "ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop"){
                    return $retCompliant
                }
            }
            else{
                $test = nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'
                if($test -match 'ip6 saddr ::1 counter packets 0 bytes 0 drop'){
                    return $retCompliant
                }
            }
            return $retNonCompliant
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.2.7"
    Task = "Ensure nftables outbound and established connections are configured"
    Test = {
        try{
            if ($FirewallStatus -match 2) {
                return $retUsingFW1
            }
            if ($FirewallStatus -match 3) {
                return $retUsingFW3
            }
            $test1 = nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
            $test2 = nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'
            if($test1 -match "ip protocol tcp ct state established accept" -and $test1 -match "p protocol udp ct state established accept" -and $test1 -match "ip protocol icmp ct state established accept" -and $test2 -match "ip protocol tcp ct state established,related,new accep" -and $test2 -match "ip protocol udp ct state established,related,new accept" -and $test2 -match "ip protocol icmp ct state established,related,new accept"){
                return $retCompliant
            }
            return $retNonCompliant
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.2.8"
    Task = "Ensure nftables default deny firewall policy"
    Test = {
        try{
            if ($FirewallStatus -match 2) {
                return $retUsingFW1
            }
            if ($FirewallStatus -match 3) {
                return $retUsingFW3
            }
            $test1 = nft list ruleset | grep 'hook input'
            $test2 = nft list ruleset | grep 'hook forward'
            $test3 = nft list ruleset | grep 'hook output'
            if($test1 -match "policy drop" -and $test2 -match "policy drop" -and $test3 -match "policy drop"){
                return $retCompliant
            }
            return $retNonCompliant
        }
        catch{
            return @{
                Message = "Command not found!"
                Status = "False"
            }
        }
    }
}
[AuditTest] @{
    Id = "4.2.9"
    Task = "Ensure nftables service is enabled"
    Test = {
        if ($FirewallStatus -match 2) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $test1 = systemctl is-enabled nftables
        if($test1 -match "enabled"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.2.10"
    Task = "Ensure nftables rules are permanent"
    Test = {
        if ($FirewallStatus -match 2) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 3) {
            return $retUsingFW3
        }
        $path1 = $scriptPath + "3.5.2.10_1.sh"
        $path2 = $scriptPath + "3.5.2.10_2.sh"
        $path3 = $scriptPath + "3.5.2.10_3.sh"
        if($path1 -ne $null -and $path2 -ne $null -and $path3 -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.3.1.1"
    Task = "Ensure iptables packages are installed"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 2) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName iptables-persistent
        if($test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.3.1.2"
    Task = "Ensure nftables is not installed with iptables"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 2) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName nftables
        if(! $test1){
            return $retNonCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "4.3.1.3"
    Task = "Ensure ufw is uninstalled or disabled with iptables"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 2) {
            return $retUsingFW3
        }
        $test1 = Test-PackageInstalled -PackageName ufw
        if(! $test1){
            return $retCompliant
        } else {
            $test2 = /usr/sbin/ufw status | grep -iE "Status: Ina[ck]tive?"
            $test3 = systemctl is-enabled ufw
            if($test2 -ne $null -and $test3 -match "masked") {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.3.2.1"
    Task = "Ensure iptables default deny firewall policy"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 2) {
            return $retUsingFW3
        }
        $output = /usr/sbin/iptables -L
        $test1 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $test2 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $test3 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        if($test1 -ne $null -and $test2 -ne $null -and $test3 -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.3.2.2"
    Task = "Ensure iptables loopback traffic is configured"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 2) {
            return $retUsingFW3
        }
        $test1 = /usr/sbin/iptables -L INPUT -v -n | grep "Chain\s*INPUT\s*(policy\s*DROP"
        $test2 = /usr/sbin/iptables -L OUTPUT -v -n | grep "Chain\s*OUTPUT\s*(policy\s*DROP"
        if($test1 -ne $null -and $test2 -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.3.2.3"
    Task = "Ensure iptables outbound and established connections are configured"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 2) {
            return $retUsingFW3
        }
        $test1 = /usr/sbin/iptables -L -v -n
        if($test1 -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
# 3.5.3.2.4 ...

[AuditTest] @{ # in CIS it's automated, but in Excelsheet it's manual
    Id = "4.3.2.4"
    Task = "Ensure iptables firewall rules exist for all open ports"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "4.3.3.1"
    Task = "Ensure ip6tables default deny firewall policy"
    Test = {
        if ($FirewallStatus -match 1) {
            return $retUsingFW1
        }
        if ($FirewallStatus -match 2) {
            return $retUsingFW3
        }
        $output = /usr/sbin/ip6tables -L
        $test11 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $test12 = $output -match "REJECT" | grep "Chain INPUT (policy REJECT)"
        $test21 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        $test22 = $output -match "REJECT" | grep "Chain OUTPUT (policy REJECT)"
        $test31 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $test32 = $output -match "REJECT" | grep "Chain FORWARD (policy REJECT)"

        if ($IPv6Status -eq $false) {
            return @{
                Message = "IPv6 is disabled"
                Status = "True"
            }
        }
        if(($test11 -ne $null -or $test12 -ne $null) -and ($test21 -ne $null -or $test22 -ne $null) -and ($test31 -ne $null -or $test32 -ne $null)){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "4.3.3.2"
    Task = "Ensure ip6tables loopback traffic is configured"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "4.3.3.3"
    Task = "Ensure ip6tables outbound and established connections are configured"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "4.3.3.4"
    Task = "Ensure ip6tables firewall rules exist for all open ports"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "5.1.1"
    Task = "Ensure cron daemon is enabled and running"
    Test = {
        $test1 = systemctl is-enabled cron
        $test2 = systemctl status cron | grep 'Active: active (running) '
        if($test1 -eq "enabled" -and $test2 -match "running"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "5.1.2"
    Task = "Ensure permissions on /etc/crontab are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/crontab | grep -q "0600"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "5.1.3"
    Task = "Ensure permissions on SSH public host key files are configured"
    Test = {
        $script = $commonPath + "5.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.4"
    Task = "Ensure sshd access is configured"
    Test = {
        if (sshd -T | grep -Piq -- "^\h*(allow|deny)(users|groups)\h+\H+") {
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "5.1.5"
    Task = "Ensure sshd Banner is configured"
    Test = {
        if (sshd -T | grep -Piq -- "^\h*banner\h+\H+") {
            return $retCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "5.1.6"
    Task = "Ensure sshd Ciphers are configured"
    Test = {
        $script = $scriptPath + "5.1.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.7"
    Task = "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"
    Test = {
        $script = $scriptPath + "5.1.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.8"
    Task = "Ensure sshd DisableForwarding is enabled"
    Test = {
        $script = $scriptPath + "5.1.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.9"
    Task = "Ensure sshd GSSAPIAuthentication is disabled"
    Test = {
        $script = $scriptPath + "5.1.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.10"
    Task = "Ensure sshd HostbasedAuthentication is disabled"
    Test = {
        $script = $scriptPath + "5.1.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.11"
    Task = "Ensure sshd IgnoreRhosts is enabled"
    Test = {
        $script = $scriptPath + "5.1.11.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.12"
    Task = "Ensure sshd KexAlgorithms is configured"
    Test = {
        $script = $scriptPath + "5.1.12.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.13"
    Task = "Ensure sshd LoginGraceTime is configured"
    Test = {
        $script = $scriptPath + "5.1.13.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.14"
    Task = "Ensure sshd LogLevel is configured"
    Test = {
        $script = $scriptPath + "5.1.14.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.15"
    Task = "Ensure sshd MACs are configured"
    Test = {
        $script = $scriptPath + "5.1.15.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.16"
    Task = "Ensure sshd MaxAuthTries is configured"
    Test = {
        $script = $commonPath + "5.1.16.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.17"
    Task = "Ensure sshd MaxSessions is configured"
    Test = {
        $script = $scriptPath + "5.1.17.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.18"
    Task = "Ensure sshd MaxStartups is configured"
    Test = {
        $script = $scriptPath + "5.1.18.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.19"
    Task = "Ensure sshd PermitEmptyPasswords is disabled"
    Test = {
        $script = $commonPath + "5.1.19.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.20"
    Task = "Ensure sshd PermitRootLogin is disabled"
    Test = {
        $script = $commonPath + "5.1.20.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.21"
    Task = "Ensure sshd PermitUserEnvironment is disabled"
    Test = {
        $script = $commonPath + "5.1.21.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.1.22"
    Task = "Ensure sshd UsePAM is enabled"
    Test = {
        $script = $commonPath + "5.1.22.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.2.1"
    Task = "Ensure sudo is installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName sudo
        if($test1){
            return $retNonCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "5.2.2"
    Task = "Ensure sudo commands use pty"
    Test = {
        $script = $commonPath + "5.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.2.3"
    Task = "Ensure sudo log file exists"
    Test = {
        $script = $commonPath + "5.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.2.4"
    Task = "Ensure users must provide password for privilege escalation"
    Test = {
        $script = $scriptPath + "5.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.2.5"
    Task = "Ensure re-authentication for privilege escalation is not disabled globally"
    Test = {
        $script = $scriptPath + "5.2.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.2.6"
    Task = "Ensure sudo authentication timeout is configured correctly"
    Test = {
        $script = $commonPath + "5.2.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
} 
[AuditTest] @{
    Id = "5.2.7"
    Task = "Ensure access to the su command is restricted"
    Test = {
        $script = $scriptPath + "5.2.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.1.1"
    Task = "Ensure latest version of pam is installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName libpam-runtime
        if($test1){
            return $retNonCompliant
        }
        return $retCompliant
    }
} 
[AuditTest] @{
    Id = "5.3.1.2"
    Task = "Ensure libpam-modules is installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName libpam-modules
        if($test1){
            return $retNonCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "5.3.1.3"
    Task = "Ensure libpam-pwquality is installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName libpam-pwquality
        if($test1){
            return $retNonCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "5.3.2.1"
    Task = "Ensure pam_unix module is enabled"
    Test = {
        $script = $scriptPath + "5.3.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.2.2"
    Task = "Ensure pam_faillock module is enabled"
    Test = {
        $script = $scriptPath + "5.3.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.2.3"
    Task = "Ensure pam_pwquality module is enabled"
    Test = {
        $script = $scriptPath + "5.3.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.2.4"
    Task = "Ensure pam_pwhistory module is enabled"
    Test = {
        $script = $scriptPath + "5.3.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.1.1"
    Task = "Ensure password failed attempts lockout is configured"
    Test = {
        $script = $commonPath + "5.3.3.1.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.1.2"
    Task = "Ensure password unlock time is configured"
    Test = {
        $script = $commonPath + "5.3.3.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.1.3"
    Task = "Ensure password failed attempts lockout includes root account"
    Test = {
        $script = $commonPath + "5.3.3.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.1"
    Task = "Ensure password number of changed characters is configured"
    Test = {
        $script = $commonPath + "5.3.3.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.2"
    Task = "Ensure minimum password length is configured"
    Test = {
        $script = $commonPath + "5.3.3.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.3"
    Task = "Ensure password complexity is configured"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "5.3.3.2.4"
    Task = "Ensure password same consecutive characters is configured"
    Test = {
        $script = $commonPath + "5.3.3.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.5"
    Task = "Ensure password maximum sequential characters is configured"
    Test = {
        $script = $commonPath + "5.3.3.2.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.6"
    Task = "Ensure password dictionary check is enabled"
    Test = {
        $script = $commonPath + "5.3.3.2.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.7"
    Task = "Ensure password quality checking is enforced"
    Test = {
        $script = $scriptPath + "5.3.3.2.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.2.8"
    Task = "Ensure password quality is enforced for the root user"
    Test = {
        $script = $scriptPath + "5.3.3.2.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.3.1"
    Task = "Ensure password history remember is configured"
    Test = {
        $script = $scriptPath + "5.3.3.3.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.3.2"
    Task = "Ensure password history is enforced for the root user"
    Test = {
        $script = $scriptPath + "5.3.3.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.3.3"
    Task = "Ensure pam_pwhistory includes use_authtok"
    Test = {
        $script = $commonPath + "5.3.3.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.4.1"
    Task = "Ensure pam_unix does not include nullok"
    Test = {
        $script = $commonPath + "5.3.3.4.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.4.2"
    Task = "Ensure pam_unix does not include remember"
    Test = {
        $script = $scriptPath + "5.3.3.4.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.4.3"
    Task = "Ensure pam_unix includes a strong password hashing algorithm"
    Test = {
        $script = $scriptPath + "5.3.3.4.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.3.3.4.4"
    Task = "Ensure pam_unix includes use_authtok"
    Test = {
        $script = $commonPath + "5.3.3.4.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.1"
    Task = "Ensure password expiration is configured"
    Test = {
        $script = $commonPath + "5.4.1.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.2"
    Task = "Ensure minimum password age is configured"
    Test = {
        $script = $commonPath + "5.4.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.3"
    Task = "Ensure password expiration warning days is configured"
    Test = {
        $script = $commonPath + "5.4.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.4"
    Task = "Ensure strong password hashing algorithm is configured"
    Test = {
        $script = $commonPath + "5.4.1.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.5"
    Task = "Ensure inactive password lock is configured"
    Test = {
        $script = $commonPath + "5.4.1.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.1.6"
    Task = "Ensure all users last password change date is in the past"
    Test = {
        $path = $scriptPath + "5.5.1.5.sh"
        $result = bash $path
        if($result -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "5.4.2.1"
    Task = "Ensure root is the only UID 0 account"
    Test = {
        $test1 = awk -F: '($3 == 0) { print $1 }' /etc/passwd
        if($test1 -match "root"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
     Id = "5.4.2.2"
     Task = "Ensure root is the only GID 0 account"
     Test = {
         $test1 = grep "^root:" /etc/passwd | cut -f4 -d ':'
         if($test1 -eq 0){
             return $retCompliant
         }
         return $retNonCompliant
     }
 }
 [AuditTest] @{
    Id = "5.4.2.3"
    Task = "Ensure group root is the only GID 0 group"
    Test = {
        $script = $commonPath + "5.4.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.2.4"
    Task = "Ensure root password is set"
    Test = {
        $script = $scriptPath + "5.4.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.2.5"
    Task = "Ensure root PATH Integrity"
    Test = {
        $path = $scriptPath + "6.2.9.sh"
        $result = bash $path
        if($result -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "5.4.2.6"
    Task = "Ensure root user umask is configured"
    Test = {
        $script = $commonPath + "5.4.2.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.2.7"
    Task = "Ensure system accounts do not have a valid login shell"
    Test = {
        $script = $commonPath + "5.4.2.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.2.8"
    Task = "Ensure accounts without a valid login shell are locked"
    Test = {            
        $script = $commonPath + "5.4.2.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "5.4.3.1"
    Task = "Ensure nologin is not listed in /etc/shells"
    Test = {
        $script = $commonPath + "5.4.3.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.3.2"
    Task = "Ensure default user shell timeout is configured"
    Test = {
        $script = $commonPath + "5.4.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "5.4.3.3"
    Task = "Ensure default user umask is configured"
    Test = {
        $script = $commonPath + "5.4.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.1.1"
    Task = "Ensure permissions on /etc/passwd are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/passwd | grep -q "0644"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.1.2"
    Task = "Ensure permissions on /etc/passwd- are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/passwd- | grep -q "0644"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.1.3"
    Task = "Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
    Test = {
        $script = $commonPath + "6.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.2.1.1.1"
    Task = "Ensure journald service is enabled and active"
    Test = {
        $test1 = systemctl is-enabled rsyslog
        if($test1 -match "enabled"){
            return @{
                Message = "Compliant"
                Status = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status = "False"
        }
    }
}
[AuditTest] @{
    Id = "6.2.1.1.2"
    Task = "Ensure journald log file access is configured"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "6.2.1.1.3"
    Task = "Ensure journald log file rotation is configured"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "6.2.1.1.4"
    Task = "Ensure journald ForwardToSyslog is disabled"
    Test = {
        $script = $scriptPath + "6.2.1.1.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.2.1.1.5"
    Task = "Ensure journald Storage is configured"
    Test = {
        $script = $scriptPath + "6.2.1.1.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.2.1.1.6"
    Task = "Ensure journald Compress is configured"
    Test = {
        $script = $scriptPath + "6.2.1.1.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.2.1.2.1"
    Task = "Ensure systemd-journal-remote is installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName systemd-journal-remote
        if($test1){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "6.2.1.2.2"
    Task = "Ensure systemd-journal-remote authentication is configured"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{
    Id = "6.2.1.2.3"
    Task = "Ensure systemd-journal-upload is enabled and active"
    Test = {
        $test1 = systemctl is-enabled systemd-journal-upload.service
        $test2 = systemctl is-active systemd-journal-upload.service
        if($test1 -eq "enabled" -and $test2 -match "active"){
            return $retCompliant
        }
        return $retCompliant
    }
}
[AuditTest] @{
    Id = "6.2.1.2.4"
    Task = "Ensure systemd-journal-remote service is not in use"
    Test = {
        $script = $scriptPath + "6.2.1.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.2.2.1"
    Task = "Ensure access to all logfiles has been configured"
    Test = {
        $fileListAll = find /var/log -type f -ls
        $fileListFiltered = find /var/log -type f -ls | grep "\-....\-\-\-\-\-"
        if($fileListAll.Count -eq $fileListFiltered.Count){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.1.1"
    Task = "Ensure auditd packages are installed"
    Test = {
        $test1 = Test-PackageInstalled -PackageName auditd
        $test2 = Test-PackageInstalled -PackageName audispd-plugins
        if($test1 -and $test2){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.1.2"
    Task = "Ensure auditd service is enabled and active"
    Test = {
        $test1 = systemctl is-enabled auditd
        if($test1 -match "enabled"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.1.3"
    Task = "Ensure auditing for processes that start prior to auditd is enabled"
    Test = {
        $script = $scriptPath + "6.3.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.1.4"
    Task = "Ensure audit_backlog_limit is sufficient"
    Test = {
        $script = $scriptPath + "6.3.1.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.2.1"
    Task = "Ensure audit log storage size is configured"
    Test = {
        $script = $commonPath + "6.3.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.2.2"
    Task = "Ensure audit logs are not automatically deleted"
    Test = {
        $script = $commonPath + "6.3.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.2.3"
    Task = "Ensure system is disabled when audit logs are full"
    Test = {
        $test1 = grep -Pi -- '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.2.4"
    Task = "Ensure system warns when audit logs are low on space"
    Test = {
        $test1 = grep -Pi -- '^\h*space_left_action\h*=\h*\w+\b' /etc/audit/auditd.conf | awk '{print $3}'
        if($test1 -match "^(email|exec|single|halt)$"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.3.1"
    Task = "Ensure changes to system administration scope is collected"
    Test = {
        $script = $commonPath + "6.3.3.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.2"
    Task = "Ensure actions as another user are always logged"
    Test = {
        $script = $commonPath + "6.3.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.3"
    Task = "Ensure events that modify the sudo log file are collected"
    Test = {
        $script = $commonPath + "6.3.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.4"
    Task = "Ensure events that modify date and time information are collected"
    Test = {
        $script = $commonPath + "6.3.3.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.5"
    Task = "Ensure events that modify the system's network environment are collected"
    Test = {
        $script = $commonPath + "6.3.3.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.6"
    Task = "Ensure use of privileged commands are collected"
    Test = {
        $script = $commonPath + "6.3.3.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.7"
    Task = "Ensure unsuccessful file access attempts are collected"
    Test = {
        $script = $commonPath + "6.3.3.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.8"
    Task = "Ensure events that modify user/group information are collected"
    Test = {
        $script = $commonPath + "6.3.3.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.9"
    Task = "Ensure discretionary access control permission modification events are collected"
    Test = {
        $script = $commonPath + "6.3.3.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.10"
    Task = "Ensure successful file system mounts are collected"
    Test = {
        $script = $commonPath + "6.3.3.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.11"
    Task = "Ensure session initiation information is collected"
    Test = {
        $path1 = $scriptPath + "4.1.3.11_1.sh"
        $result11 = bash $path1 | grep "\-w /var/run/utmp -p wa -k session"
        $result12 = bash $path1 | grep "\-w /var/log/wtmp -p wa -k session"
        $result13 = bash $path1 | grep "\-w /var/log/btmp -p wa -k session"
        $path2 = $scriptPath + "4.1.3.11_2.sh"
        $result21 = bash $path2 | grep "\-w /var/run/utmp -p wa -k session"
        $result22 = bash $path2 | grep "\-w /var/log/wtmp -p wa -k session"
        $result23 = bash $path2 | grep "\-w /var/log/btmp -p wa -k session"
        if($result11 -ne $null -and $result12 -ne $null -and $result13 -ne $null -and $result21 -ne $null -and $result22 -ne $null -and $result23 -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.3.12"
    Task = "Ensure login and logout events are collected"
    Test = {
        $script = $commonPath + "6.3.3.12.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.13"
    Task = "Ensure file deletion events by users are collected"
    Test = {
        $script = $commonPath + "6.3.3.13.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.14"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        $script = $commonPath + "6.3.3.14.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.15"
    Task = "Ensure successful and unsuccessful attempts to use the chcon command are recorded"
    Test = {
        $script = $commonPath + "6.3.3.15.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.16"
    Task = "Ensure successful and unsuccessful attempts to use the setfacl command are recorded"
    Test = {
        $script = $commonPath + "6.3.3.16.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.17"
    Task = "Ensure successful and unsuccessful attempts to use the chacl command are recorded"
    Test = {
        $script = $commonPath + "6.3.3.17.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.18"
    Task = "Ensure successful and unsuccessful attempts to use the usermod command are recorded"
    Test = {
        $script = $commonPath + "6.3.3.18.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.19"
    Task = "Ensure kernel module loading unloading and modification is collected"
    Test = {
        $script = $commonPath + "6.3.3.19.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.3.20"
    Task = "Ensure the audit configuration is immutable"
    Test = {
        $test1 = grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -l
        if($test1 -match "-e 2"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.3.21"
    Task = "Ensure the running and on disk configuration is the same"
    Test = {
        $test1 = augenrules --check
        if($test1 -match "/usr/sbin/augenrules: No change"){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "6.3.4.1"
    Task = "Ensure audit log files mode is configured"
    Test = {
        $script = $scriptPath + "6.3.4.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.2"
    Task = "Ensure audit log files owner is configured"
    Test = {
        $script = $scriptPath + "6.3.4.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.3"
    Task = "Ensure audit log files group owner is configured"
    Test = {
        $script = $scriptPath + "6.3.4.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.4"
    Task = "Ensure the audit log file directory mode is configured"
    Test = {
        $script = $scriptPath + "6.3.4.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.5"
    Task = "Ensure audit configuration files mode is configured"
    Test = {
        $script = $commonPath + "6.3.4.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.6"
    Task = "Ensure audit configuration files owner is configured"
    Test = {
        $script = $commonPath + "6.3.4.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.7"
    Task = "Ensure audit configuration files group owner is configured"
    Test = {
        $script = $commonPath + "6.3.4.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.8"
    Task = "Ensure audit tools mode is configured"
    Test = {
        $script = $commonPath + "6.3.4.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.9"
    Task = "Ensure audit tools owner is configured"
    Test = {
        $script = $commonPath + "6.3.4.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "6.3.4.10"
    Task = "Ensure audit tools group owner is configured"
    Test = {
        $test1 = stat -Lc '%G' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk '$1 != "root" {print}'
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.1"
    Task = "Ensure permissions on /etc/passwd are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/passwd | grep -q "0644"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.2"
    Task = "Ensure permissions on /etc/passwd- are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/passwd- | grep -q "0644"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.3"
    Task = "Ensure permissions on /etc/group are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/group | grep -q "0644"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.4"
    Task = "Ensure permissions on /etc/group- are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/group- | grep -q "0644"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.5"
    Task = "Ensure permissions on /etc/shadow are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/shadow | grep -q "0640"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.6"
    Task = "Ensure permissions on /etc/shadow- are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/shadow- | grep -q "0640"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.7"
    Task = "Ensure permissions on /etc/gshadow are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/gshadow | grep -q "0640"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.8"
    Task = "Ensure permissions on /etc/gshadow- are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/gshadow- | grep -q "0640"
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.9"
    Task = "Ensure permissions on /etc/shells are configured"
    Test = {
        $script = $commonPath + "7.1.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id = "7.1.10"
    Task = "Ensure permissions on /etc/security/opasswd are configured"
    Test = {
        $script = $commonPath + "7.1.10.sh"
        $result = bash $script
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.11"
    Task = "Ensure world writable files and directories are secured"
    Test = {
        #$partitions = mapfile -t partitions < (sudo fdisk -l | grep -o '/dev/[^ ]*')
        #$test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
        $script = $commonPath + "7.1.11.sh"
        $result = bash $script
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.1.12"
    Task = "Ensure no files or directories without an owner and a group exist"
    Test = {
        $script = $commonPath + "7.1.12.sh"
        $result = bash $script
        if($?){
                return $retCompliant
            }
            return $retNonCompliant
    }
} 
[AuditTest] @{
    Id = "7.1.13"
    Task = "Ensure SUID and SGID files are reviewed"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000
        $message = ""
        foreach($line in $test1){
            $message += "<br>$line"
        }
        return @{
            Message = "Please review following list of files: $($message)"
            Status = "None"
        }
    }
}
[AuditTest] @{
    Id = "7.2.1"
    Task = "Ensure accounts in /etc/passwd use shadowed passwords"
    Test = {
        $test1 = awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}'/etc/passwd
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.2.2"
    Task = "Ensure /etc/shadow password fields are not empty"
    Test = {
        $test1 = awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
        if($test1 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.2.3"
    Task = "Ensure all groups in /etc/passwd exist in /etc/group"
    Test = {
        $path = $scriptPath + "6.2.3.sh"
        $result = bash $path
        if($?){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.2.4"
    Task = "Ensure shadow group is empty"
    Test = {
        $test1 = awk -F: '($1=="shadow") {print $NF}' /etc/group
        $test2 = awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd
        if($test1.Length -eq 0 -and $test2 -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.2.5"
    Task = "Ensure no duplicate UIDs exist"
    Test = {
        $path = $scriptPath + "6.2.5.sh"
        $result = bash $path
        if($result -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.2.6"
    Task = "Ensure no duplicate GIDs exist"
    Test = {
        $path = $scriptPath + "6.2.6.sh"
        $result = bash $path
        if($result -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.2.7"
    Task = "Ensure no duplicate user names exist"
    Test = {
        $path = $scriptPath + "6.2.7.sh"
        $result = bash $path
        if($result -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id = "7.2.8"
    Task = "Ensure no duplicate group names exist"
    Test = {
        $path = $scriptPath + "6.2.8.sh"
        $result = bash $path
        if($result -eq $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{ # in CIS it's automated, but in Excelsheet it's manual
    Id = "7.2.9"
    Task = "Ensure local interactive user home directories are configured"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
[AuditTest] @{ # in CIS it's automated, but in Excelsheet it's manual
    Id = "7.2.10"
    Task = "Ensure local interactive user dot files access is configured"
    Test = {
        	return $retNonCompliantManualReviewRequired
    }
}
