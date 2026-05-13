$rcTrue = "True"
$rcCompliant = "Compliant"
$rcFalse = "False"
$rcNone = "None"
$rcNonCompliant = "Non-Compliant"
$rcNonCompliantManualReviewRequired = "Manual review required"
$rcCompliantIPv6isDisabled = "IPv6 is disabled"

$retCompliant = @{
    Message = $rcCompliant
    Status  = $rcTrue
}
$retNonCompliant = @{
    Message = $rcNonCompliant
    Status  = $rcFalse
}
$retCompliantIPv6Disabled = @{
    Message = $rcCompliantIPv6isDisabled
    Status  = $rcTrue
}
$retNonCompliantManualReviewRequired = @{
    Message = $rcNonCompliantManualReviewRequired
    Status  = $rcNone
}

$IPv6Status_script = grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && echo "IPv6 is enabled" || echo "IPv6 is not enabled"
$IPv6Status = bash -c $IPv6Status_script
if ($IPv6Status -match "is enabled") {
    $IPv6Status = "enabled"
}
else {
    $IPv6Status = "disabled"
}

$parentPath = Split-Path -Parent -Path $PSScriptRoot
$scriptPath = $parentPath + "/Helpers/ShellScripts/RHEL9_CIS2.0.0/"
$commonPath = $parentPath + "/Helpers/ShellScripts/common/"

[AuditTest] @{
    Id   = "1.1.1.1"
    Task = "Ensure cramfs kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.2"
    Task = "Ensure freevxfs kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.3"
    Task = "Ensure hfs kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.4"
    Task = "Ensure hfsplus kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.5"
    Task = "Ensure jffs2 kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.6"
    Task = "Ensure squashfs kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.7"
    Task = "Ensure udf kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.1.8"
    Task = "Ensure usb-storage kernel module is not available"
    Test = {
        $script = $commonPath + "1.1.1.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 1.1.1.9 - Ensure unused filesystems kernel modules are not available
[AuditTest] @{
    Id   = "1.1.2.1.1"
    Task = "Ensure /tmp is a separate partition"
    Test = {
        $result = findmnt --kernel /tmp | grep -E '\s/tmp\s'
        if ($result -match "/tmp") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.1.2.1.2"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.1.3"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.1.4"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result = findmnt --kernel /tmp | grep noexec
        if ($result -match "/tmp") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.1.2.2.1"
    Task = "Ensure /dev/shm is a separate partition"
    Test = {
        $result = findmnt --kernel /dev/shm
        if ($result -match "/dev/shm") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.1.2.2.2"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $script = $commonPath + "1.1.2.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.2.3"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $script = $commonPath + "1.1.2.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.2.4"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $script = $commonPath + "1.1.2.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.3.1"
    Task = "Ensure separate partition exists for /home"
    Test = {
        $result = findmnt --kernel /home
        if ($result -match "/home") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.1.2.3.2"
    Task = "Ensure nodev option set on /home partition"
    Test = {
        $script = $commonPath + "1.1.2.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.3.3"
    Task = "Ensure nosuid option set on /home partition"
    Test = {
        $script = $commonPath + "1.1.2.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.4.1"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result = findmnt --kernel /var
        if ($result -match "/var") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}



[AuditTest] @{
    Id   = "1.1.2.4.2"
    Task = "Ensure nodev option set on /var partition"
    Test = {
        $script = $commonPath + "1.1.2.4.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.4.3"
    Task = "Ensure nosuid option set on /var partition"
    Test = {
        $script = $commonPath + "1.1.2.4.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.5.1"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result = findmnt --kernel /var/tmp
        if ($result -match "/var/tmp") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.1.2.5.2"
    Task = "Ensure nodev option set on /var/tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.5.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.5.3"
    Task = "Ensure nosuid option set on /var/tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.5.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.5.4"
    Task = "Ensure noexec option set on /var/tmp partition"
    Test = {
        $script = $commonPath + "1.1.2.5.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.6.1"
    Task = "Ensure separate partition exists for /var/log"
    Test = {
        $result = findmnt --kernel /var/log
        if ($result -match "/var/log") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.1.2.6.2"
    Task = "Ensure nodev option set on /var/log partition"
    Test = {
        $script = $commonPath + "1.1.2.6.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.6.3"
    Task = "Ensure nosuid option set on /var/log partition"
    Test = {
        $script = $commonPath + "1.1.2.6.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.6.4"
    Task = "Ensure noexec option set on /var/log partition"
    Test = {
        $script = $commonPath + "1.1.2.6.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.7.1"
    Task = "Ensure separate partition exists for /var/log/audit"
    Test = {
        $result = findmnt --kernel /var/log/audit
        if ($result -match "/var/log/audit") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.1.2.7.2"
    Task = "Ensure nodev option set on /var/log/audit partition"
    Test = {
        $script = $commonPath + "1.1.2.7.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.7.3"
    Task = "Ensure nosuid option set on /var/log/audit partition"
    Test = {
        $script = $commonPath + "1.1.2.7.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.1.2.7.4"
    Task = "Ensure noexec option set on /var/log/audit partition"
    Test = {
        $script = $commonPath + "1.1.2.7.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.2.1.1"
    Task = "Ensure GPG keys are configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}


[AuditTest] @{
    Id   = "1.2.1.2"
    Task = "Ensure gpgcheck is globally activated"
    Test = {
        $script = $scriptPath + "1.2.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.2.1.3"
    Task = "Ensure repo_gpgcheck is globally activated"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}


[AuditTest] @{
    Id   = "1.2.1.4"
    Task = "Ensure package manager repositories are configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}


[AuditTest] @{
    Id   = "1.2.2.1"
    Task = "Ensure updates, patches, and additional security software are installed"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}


[AuditTest] @{
    Id   = "1.3.1.1"
    Task = "Ensure SELinux is installed"
    Test = {
        rpm -q libselinux 2>&1 >/dev/null
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.3.1.2"
    Task = "Ensure SELinux is not disabled in bootloader configuration"
    Test = {
        $script = $scriptPath + "1.3.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.3.1.3"
    Task = "Ensure SELinux policy is configured"
    Test = {
        $script = $scriptPath + "1.3.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.3.1.4"
    Task = "Ensure the SELinux mode is not disabled"
    Test = {
        $result1 = getenforce
        $result2 = grep -Ei '^\s*SELINUX=(enforcing|permissive)' /etc/selinux/config
        if (($result1 -match "Enforcing" -or $result1 -match "Permissive") -and ($result2 -match "SELINUX=enforcing" -or $result2 -match "SELINUX=permissive")) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.3.1.5"
    Task = "Ensure the SELinux mode is enforcing"
    Test = {
        $script = $scriptPath + "1.3.1.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 1.3.1.6 - Ensure no unconfined services exist
[AuditTest] @{
    Id   = "1.3.1.7"
    Task = "Ensure the MCS Translation Service (mcstrans) is not installed"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd
        if ($result -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.3.1.8"
    Task = "Ensure SETroubleshoot is not installed"
    Test = {
        rpm -q setroubleshoot 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.4.1"
    Task = "Ensure bootloader password is set"
    Test = {
        $result = awk -F. '/^\s*GRUB2_PASSWORD/ {print $1"."$2"."$3}' /boot/grub2/user.cfg
        if ($result -match "GRUB2_PASSWORD=grub.pbkdf2.sha512") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.4.2"
    Task = "Ensure access to bootloader config is configured"
    Test = {
        $script = $commonPath + "1.4.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.5.1"
    Task = "Ensure address space layout randomization is enabled"
    Test = {
        $script = $commonPath + "1.5.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.5.2"
    Task = "Ensure ptrace_scope is restricted"
    Test = {
        $script = $commonPath + "1.5.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.5.3"
    Task = "Ensure core dump backtraces are disabled"
    Test = {
        $script = $scriptPath + "1.5.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.5.4"
    Task = "Ensure core dump storage is disabled"
    Test = {
        $script = $scriptPath + "1.5.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.6.1"
    Task = "Ensure system wide crypto policy is not set to legacy"
    Test = {
        $script = $scriptPath + "1.6.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.6.2"
    Task = "Ensure system wide crypto policy is not set in sshd configuration"
    Test = {
        $script = $scriptPath + "1.6.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 1.6.3 - Ensure system wide crypto policy disables sha1 hash and signature support
# MISSING RULE: 1.6.4 - Ensure system wide crypto policy disables macs less than 128 bits
# MISSING RULE: 1.6.5 - Ensure system wide crypto policy disables cbc for ssh
# MISSING RULE: 1.6.6 - Ensure system wide crypto policy disables chacha20-poly1305 for ssh
# MISSING RULE: 1.6.7 - Ensure system wide crypto policy disables EtM for ssh
[AuditTest] @{
    Id   = "1.7.1"
    Task = "Ensure message of the day is configured properly"
    Test = {
        $script = $scriptPath + "1.7.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.7.2"
    Task = "Ensure local login warning banner is configured properly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
        if ($result -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.7.3"
    Task = "Ensure remote login warning banner is configured properly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net
        if ($result -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.7.4"
    Task = "Ensure access to /etc/motd is configured"
    Test = {
        $script = $scriptPath + "1.7.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "1.7.5"
    Task = "Ensure permissions on /etc/issue are configured"
    Test = {
        $result = stat -c "%a" /etc/issue
        if ($result -eq 644) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.7.6"
    Task = "Ensure permissions on /etc/issue.net are configured"
    Test = {
        $result = stat -c "%a" /etc/issue.net
        if ($result -eq 644) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.1"
    Task = "Ensure GNOME Display Manager is removed"
    Test = {
        rpm -q gdm 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.2"
    Task = "Ensure GDM login banner is configured"
    Test = {
        $resultScript = $scriptPath + "1.8.2.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.3"
    Task = "Ensure GDM disable-user-list option is enabled"
    Test = {
        $resultScript = $scriptPath + "1.8.3.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.4"
    Task = "Ensure GDM screen locks when the user is idle"
    Test = {
        $resultScript = $scriptPath + "1.8.4.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.5"
    Task = "Ensure GDM screen locks cannot be overridden"
    Test = {
        $resultScript = $scriptPath + "1.8.5.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.6"
    Task = "Ensure GDM automatic mounting of removable media is disabled"
    Test = {
        $resultScript = $scriptPath + "1.8.6.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.7"
    Task = "Ensure GDM disabling automatic mounting of removable media is not overridden"
    Test = {
        $resultScript = $scriptPath + "1.8.7.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.8"
    Task = "Ensure GDM autorun-never is enabled"
    Test = {
        $resultScript = $scriptPath + "1.8.8.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.9"
    Task = "Ensure GDM autorun-never is not overridden"
    Test = {
        $resultScript = $scriptPath + "1.8.9.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "1.8.10"
    Task = "Ensure XDMCP is not enabled"
    Test = {
        $script = $scriptPath + "1.8.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "2.1.1"
    Task = "Ensure time synchronization is in use"
    Test = {
        rpm -q chrony 2>&1 >/dev/null
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.1.2"
    Task = "Ensure chrony is configured"
    Test = {
        $test = grep -E "^(server|pool)" /etc/chrony.conf | grep OPTIONS\s*-u\s*chrony
        if ($test -match "OPTIONS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.1.3"
    Task = "Ensure dhcp server services are not in use"
    Test = {
        rpm -q isc-dhcp-server 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null isc-dhcp-server.service
            if (! $?) {
                $test2 = systemctl is-enabled 2>/dev/null isc-dhcp-server6.service
                if (! $?) {
                    return $retCompliant
                }
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.4"
    Task = "Ensure dns server services are not in use"
    Test = {
        rpm -q bind9 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null bind9.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

# MISSING RULE: 2.1.5 - Ensure dnsmasq services are not in use
[AuditTest] @{
    Id   = "2.1.6"
    Task = "Ensure samba file server services are not in use"
    Test = {
        rpm -q samba 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null samba.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.7"
    Task = "Ensure ftp server services are not in use"
    Test = {
        rpm -q vsftpd 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null vsftpd.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.8"
    Task = "Ensure message access server services are not in use"
    Test = {
        rpm -q dovecot-imapd 2>&1 >/dev/null
        if ($?) {
            return $retNonCompliant
        }
        rpm -q dovecot-pop3d 2>&1 >/dev/null
        if ($?) {
            return $retNonCompliant
        }
        $test3 = systemctl is-enabled 2>/dev/null dovecot.socket
        if (! $?) {
            $test4 = systemctl is-enabled 2>/dev/null dovecot.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.9"
    Task = "Ensure network file system services are not in use"
    Test = {
        rpm -q nfs-kernel-server 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null nfs-kernel.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.10"
    Task = "Ensure nis server services are not in use"
    Test = {
        rpm -q ypserv 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null ypserv.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.11"
    Task = "Ensure print server services are not in use"
    Test = {
        rpm -q cups 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null cups.service
            if (! $?) {
                $test3 = systemctl is-enabled 2>/dev/null cups.socket
                if (! $?) {
                    return $retCompliant
                }
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.12"
    Task = "Ensure rpcbind services are not in use"
    Test = {
        rpm -q rpcbind 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null rpcbind.service
            if (! $?) {
                $test3 = systemctl is-enabled 2>/dev/null rpcbind.socket
                if (! $?) {
                    return $retCompliant
                }
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.13"
    Task = "Ensure rsync services are not in use"
    Test = {
        $script = $commonPath + "2.1.13.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.15"
    Task = "Ensure snmp services are not in use"
    Test = {
        rpm -q snmpd 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null snmpd.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

# MISSING RULE: 2.1.15 - Ensure telnet server services are not in use
[AuditTest] @{
    Id   = "2.1.16"
    Task = "Ensure tftp server services are not in use"
    Test = {
        rpm -q tftpd-hpa 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null tftpd-hpa.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.17"
    Task = "Ensure web proxy server services are not in use"
    Test = {
        rpm -q squid 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null squid.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.18"
    Task = "Ensure web server services are not in use"
    Test = {
        rpm -q apache2 2>&1 >/dev/null
        if ($?) {
            return $retNonCompliant
        }
        rpm -q ginx 2>&1 >/dev/null
        if ($?) {
            return $retNonCompliant
        }
        else {
            $services = 'apache2.service', 'apache2.socket', 'nginx.service', 'nginx.socket'
            $test3 = "disabled"
            foreach ($service in $services) {
                $test4 = systemctl is-enabled $service 2>/dev/null
                if ($?) {
                    $test3 = "enabled"
                }
            }
            if ($test3 -match "disabled") {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.19"
    Task = "Ensure xinetd services are not in use"
    Test = {
        rpm -q xinetd 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            $test2 = systemctl is-enabled 2>/dev/null xinetd.service
            if (! $?) {
                return $retCompliant
            }
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "2.1.20"
    Task = "Ensure X window server services are not in use"
    Test = {
        rpm -q xserver-commen 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

# MISSING RULE: 2.1.21 - Ensure mail transfer agents are configured for local-only mode
[AuditTest] @{
    Id   = "2.1.22"
    Task = "Ensure only approved services are listening on a network interface"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id   = "2.2.1"
    Task = "Ensure xorg-x11-server-common is not installed"
    Test = {
        rpm -q xorg-x11-server-common 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.2.2"
    Task = "Ensure Avahi Server is not installed"
    Test = {
        rpm -q avahi 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.2.3"
    Task = "Ensure CUPS is not installed"
    Test = {
        rpm -q cups 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.2.4"
    Task = "Ensure DHCP Server is not installed"
    Test = {
        rpm -q dhcp-server 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.2.5"
    Task = "Ensure DNS Server is not installed"
    Test = {
        rpm -q bind 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.3.2"
    Task = "Ensure LDAP client is not installed"
    Test = {
        rpm -q openldap-clients 2>&1 >/dev/null
        if (! $?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.3.3"
    Task = "Ensure chrony is not run as the root user"
    Test = {
        $script = $scriptPath + "2.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "2.4.1.1"
    Task = "Ensure cron daemon is enabled and active"
    Test = {
        $test1 = systemctl is-enabled cron
        $test2 = systemctl status cron | grep 'Active: active (running) '
        if ($test1 -eq "enabled" -and $test2 -match "running") {
            return $retCompliant
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id   = "2.4.1.2"
    Task = "Ensure permissions on /etc/crontab are configured"
    Test = {
        $result1 = stat -c "%a" /etc/crontab
        if ($result1 -eq 600 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.4.1.3"
    Task = "Ensure permissions on /etc/cron.hourly are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.hourly
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.4.1.4"
    Task = "Ensure permissions on /etc/cron.daily are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.daily
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.4.1.5"
    Task = "Ensure permissions on /etc/cron.weekly are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.weekly
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.4.1.6"
    Task = "Ensure permissions on /etc/cron.monthly are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.monthly
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.4.1.7"
    Task = "Ensure permissions on /etc/cron.d are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.d
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "2.4.1.8"
    Task = "Ensure crontab is restricted to authorized users"
    Test = {
        $script = $commonPath + "2.4.1.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "2.4.2.1"
    Task = "Ensure at is restricted to authorized users"
    Test = {
        $script = $commonPath + "2.4.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.1.1"
    Task = "Ensure IPv6 status is identified"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}


[AuditTest] @{
    Id   = "3.1.2"
    Task = "Ensure wireless interfaces are disabled"
    Test = {
        $script = $commonPath + "3.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.1.3"
    Task = "Ensure TIPC is disabled"
    Test = {
        $resultScript = $scriptPath + "3.1.3.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "3.2.1"
    Task = "Ensure dccp kernel module is not available"
    Test = {
        $script = $commonPath + "3.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.2.2"
    Task = "Ensure tipc kernel module is not available"
    Test = {
        $script = $commonPath + "3.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.2.3"
    Task = "Ensure rds kernel module is not available"
    Test = {
        $script = $commonPath + "3.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.2.4"
    Task = "Ensure sctp kernel module is not available"
    Test = {
        $script = $commonPath + "3.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.1"
    Task = "Ensure ip forwarding is disabled"
    Test = {
        $script = $commonPath + "3.3.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.2"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $script = $commonPath + "3.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.3"
    Task = "Ensure bogus icmp responses are ignored"
    Test = {
        $script = $commonPath + "3.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.4"
    Task = "Ensure broadcast icmp requests are ignored"
    Test = {
        $script = $commonPath + "3.3.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.5"
    Task = "Ensure icmp redirects are not accepted"
    Test = {
        $script = $commonPath + "3.3.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.6"
    Task = "Ensure secure icmp redirects are not accepted"
    Test = {
        $script = $commonPath + "3.3.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.7"
    Task = "Ensure reverse path filtering is enabled"
    Test = {
        $script = $commonPath + "3.3.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.8"
    Task = "Ensure source routed packets are not accepted"
    Test = {
        $script = $commonPath + "3.3.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.9"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $script = $commonPath + "3.3.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.10"
    Task = "Ensure tcp syn cookies is enabled"
    Test = {
        $script = $commonPath + "3.3.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "3.3.11"
    Task = "Ensure ipv6 router advertisements are not accepted"
    Test = {
        $script = $commonPath + "3.3.11.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "4.1.1"
    Task = "Ensure nftables is installed"
    Test = {
        rpm -q nftables 2>&1 >/dev/null
        if ($result -match "nftables-") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "4.1.2"
    Task = "Ensure a single firewall configuration utility is in use"
    Test = {
        $resultScript = $scriptPath + "4.1.2.sh"
        $result = bash $resultScript
        if ($result -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "4.2.1"
    Task = "Ensure firewalld drops unnecessary services and ports"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}


# MISSING RULE: 4.2.2 - Ensure firewalld loopback traffic is configured
[AuditTest] @{
    Id   = "4.3.1"
    Task = "Ensure nftables base chains exist"
    Test = {
        try {
            $test1 = nft list ruleset | grep 'hook input'
            $test2 = nft list ruleset | grep 'hook forward'
            $test3 = nft list ruleset | grep 'hook output'
            if ($test1 -match "type filter hook input" -and $test2 -match "type filter hook forward" -and $test3 -match "type filter hook output") {
                return @{
                    Message = "Compliant"
                    Status  = "True"
                }
            }
            return @{
                Message = "Not-Compliant"
                Status  = "False"
            }
        }
        catch {
            return @{
                Message = "Command not found!"
                Status  = "False"
            }
        }
    }
}


[AuditTest] @{
    Id   = "4.3.2"
    Task = "Ensure nftables established connections are configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}


[AuditTest] @{
    Id   = "4.3.3"
    Task = "Ensure nftables default deny firewall policy"
    Test = {
        $result1 = systemctl --quiet is-enabled nftables.service && nft list ruleset | grep 'hook input' | grep -v 'policy drop'
        $result2 = systemctl --quiet is-enabled nftables.service && nft list ruleset | grep 'hook forward' | grep -v 'policy drop'
        if ($result1 -eq $null -and $result2 -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


### Chapter 4 - Logging and Auditing

[AuditTest] @{
    Id   = "4.3.4"
    Task = "Ensure nftables loopback traffic is configured"
    Test = {
        try {
            if ($FirewallStatus -match 2) {
                return $retUsingFW1
            }
            if ($FirewallStatus -match 3) {
                return $retUsingFW3
            }
            if ($isIPv6Disabled -ne $true) {
                $test1 = nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'
                $test2 = nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'
                if ($test1 -match 'iif "lo" accept' -and $test2 -match "ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop") {
                    return $retCompliant
                }
            }
            else {
                $test = nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'
                if ($test -match 'ip6 saddr ::1 counter packets 0 bytes 0 drop') {
                    return $retCompliant
                }
            }
            return $retNonCompliant
        }
        catch {
            return @{
                Message = "Command not found!"
                Status  = "False"
            }
        }
    }
}

[AuditTest] @{
    Id   = "5.1.1"
    Task = "Ensure cron daemon is enabled"
    Test = {
        $result1 = systemctl is-enabled crond
        if ($result1 -match "enabled") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.1.2"
    Task = "Ensure permissions on /etc/crontab are configured"
    Test = {
        $result1 = stat -c "%a" /etc/crontab
        if ($result1 -eq 600 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.1.3"
    Task = "Ensure permissions on SSH public host key files are configured"
    Test = {
        $script = $commonPath + "5.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.4"
    Task = "Ensure permissions on /etc/cron.daily are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.daily
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.1.5"
    Task = "Ensure permissions on /etc/cron.weekly are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.weekly
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.1.6"
    Task = "Ensure permissions on /etc/cron.monthly are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.monthly
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.1.7"
    Task = "Ensure permissions on /etc/cron.d are configured"
    Test = {
        $result1 = stat -c "%a" /etc/cron.d
        if ($result1 -eq 700 ) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.1.8"
    Task = "Ensure cron is restricted to authorized users"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    if rpm -q cronie 2>&1 >/dev/null >/dev/null; then
        [ -e /etc/cron.deny ] && echo "Fail: cron.deny exists"
        if [ ! -e /etc/cron.allow ]; then
            echo "Fail: cron.allow doesn't exist"
        else
            ! stat -Lc "%a" /etc/cron.allow | grep -Eq "[0,2,4,6]00" && echo "Fail: cron.allow mode too permissive"
            ! stat -Lc "%u:%g" /etc/cron.allow | grep -Eq "^0:0$" && echo "Fail: cron.allow owner and/or group not root"
        fi
        if [ ! -e /etc/cron.deny ] && [ -e /etc/cron.allow ] && stat -Lc "%a" /etc/cron.allow | grep -Eq "[0,2,4,6]00" \ && stat -Lc "%u:%g" /etc/cron.allow | grep -Eq "^0:0$"; then
            echo "Pass"
        fi
    else
        echo "PASS: cron is not installed on the system"
    fi
}
'@
        $script = bash -c $script_string
        if ($script -match "PASS") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.1.9"
    Task = "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"
    Test = {
        $script = $scriptPath + "5.1.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.10"
    Task = "Ensure sshd DisableForwarding is enabled"
    Test = {
        $script = $scriptPath + "5.1.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.11"
    Task = "Ensure sshd GSSAPIAuthentication is disabled"
    Test = {
        $script = $scriptPath + "5.1.11.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.12"
    Task = "Ensure sshd HostbasedAuthentication is disabled"
    Test = {
        $script = $scriptPath + "5.1.12.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.13"
    Task = "Ensure sshd IgnoreRhosts is enabled"
    Test = {
        $script = $scriptPath + "5.1.13.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.14"
    Task = "Ensure sshd LoginGraceTime is configured"
    Test = {
        $script = $scriptPath + "5.1.14.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.15"
    Task = "Ensure sshd LogLevel is configured"
    Test = {
        $script = $scriptPath + "5.1.15.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.16"
    Task = "Ensure sshd MaxAuthTries is configured"
    Test = {
        $script = $commonPath + "5.1.16.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.17"
    Task = "Ensure sshd MaxStartups is configured"
    Test = {
        $script = $scriptPath + "5.1.17.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.18"
    Task = "Ensure sshd MaxSessions is configured"
    Test = {
        $script = $scriptPath + "5.1.18.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.19"
    Task = "Ensure sshd PermitEmptyPasswords is disabled"
    Test = {
        $script = $commonPath + "5.1.19.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.20"
    Task = "Ensure sshd PermitRootLogin is disabled"
    Test = {
        $script = $commonPath + "5.1.20.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.21"
    Task = "Ensure sshd PermitUserEnvironment is disabled"
    Test = {
        $script = $commonPath + "5.1.21.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.1.22"
    Task = "Ensure sshd UsePAM is enabled"
    Test = {
        $script = $commonPath + "5.1.22.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.2.1"
    Task = "Ensure permissions on /etc/ssh/sshd_config are configured"
    Test = {
        $result1 = stat -Lc "%n %a %u/%U %g/%G" /etc/ssh/sshd_config
        if ($result1 -match "/etc/ssh/sshd_config 600 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.2.2"
    Task = "Ensure sudo commands use pty"
    Test = {
        $script = $commonPath + "5.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.2.3"
    Task = "Ensure sudo log file exists"
    Test = {
        $script = $commonPath + "5.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.2.4"
    Task = "Ensure SSH access is limited"
    Test = {
        $test1 = /usr/sbin/sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'
        $test2 = grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config
        if ($test1 -match "allowusers " -or $test1 -match "allowgroups " -or $test1 -match "denyusers " -or $test1 -match "denygroups " -or
            $test2 -match "allowusers " -or $test2 -match "allowgroups " -or $test2 -match "denyusers " -or $test2 -match "denygroups ") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.2.5"
    Task = "Ensure SSH LogLevel is appropriate"
    Test = {
        $test1 = /usr/sbin/sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'
        $test2 = grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config
        if (($test1 -match "allowusers " -or $test1 -match "allowgroups " -or $test1 -match "denyusers " -or $test1 -match "denygroups ") -and
            ($test2 -match "allowusers " -or $test2 -match "allowgroups " -or $test2 -match "denyusers " -or $test2 -match "denygroups ")) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.2.6"
    Task = "Ensure sudo authentication timeout is configured correctly"
    Test = {
        $script = $commonPath + "5.2.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.2.7"
    Task = "Ensure SSH root login is disabled"
    Test = {
        $test1 = /usr/sbin/sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitrootlogin
        $test2 = grep -Ei '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config
        if ($test1 -match "permitrootlogin no" -and $test2 -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.3.1.1"
    Task = "Ensure latest version of pam is installed"
    Test = {
        rpm -q libpam-runtime 2>&1 >/dev/null
        if ($?) {
            return $retNonCompliant
        }
        return $retCompliant
    }
} 

# MISSING RULE: 5.3.1.2 - Ensure latest version of authselect is installed
# MISSING RULE: 5.3.1.3 - Ensure latest version of libpwquality is installed
# MISSING RULE: 5.3.2.1 - Ensure active authselect profile includes pam modules
[AuditTest] @{
    Id   = "5.3.2.2"
    Task = "Ensure pam_faillock module is enabled"
    Test = {
        $script = $scriptPath + "5.3.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.2.3"
    Task = "Ensure pam_pwquality module is enabled"
    Test = {
        $script = $scriptPath + "5.3.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.2.4"
    Task = "Ensure pam_pwhistory module is enabled"
    Test = {
        $script = $scriptPath + "5.3.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.2.5"
    Task = "Ensure pam_unix module is enabled"
    Test = {
        $script = $scriptPath + "5.3.2.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.1.1"
    Task = "Ensure password failed attempts lockout is configured"
    Test = {
        $script = $commonPath + "5.3.3.1.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.1.2"
    Task = "Ensure password unlock time is configured"
    Test = {
        $script = $commonPath + "5.3.3.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.1.3"
    Task = "Ensure password failed attempts lockout includes root account"
    Test = {
        $script = $commonPath + "5.3.3.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.2.1"
    Task = "Ensure password number of changed characters is configured"
    Test = {
        $script = $commonPath + "5.3.3.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.2.2"
    Task = "Ensure password length is configured"
    Test = {
        $script = $commonPath + "5.3.3.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.2.3"
    Task = "Ensure password complexity is configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id   = "5.3.3.2.4"
    Task = "Ensure password same consecutive characters is configured"
    Test = {
        $script = $commonPath + "5.3.3.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.2.5"
    Task = "Ensure password maximum sequential characters is configured"
    Test = {
        $script = $commonPath + "5.3.3.2.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.2.6"
    Task = "Ensure password dictionary check is enabled"
    Test = {
        $script = $commonPath + "5.3.3.2.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.2.7"
    Task = "Ensure password quality is enforced for the root user"
    Test = {
        $script = $scriptPath + "5.3.3.2.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.3.1"
    Task = "Ensure password history remember is configured"
    Test = {
        $script = $scriptPath + "5.3.3.3.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.3.2"
    Task = "Ensure password history is enforced for the root user"
    Test = {
        $script = $scriptPath + "5.3.3.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.3.3"
    Task = "Ensure pam_pwhistory includes use_authtok"
    Test = {
        $script = $commonPath + "5.3.3.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "5.3.3.4.1"
    Task = "Ensure pam_unix does not include nullok"
    Test = {
        $script = $commonPath + "5.3.3.4.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "5.3.3.4.2"
    Task = "Ensure pam_unix does not include remember"
    Test = {
        $script = $scriptPath + "5.3.3.4.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.4.3"
    Task = "Ensure pam_unix includes a strong password hashing algorithm"
    Test = {
        $script = $scriptPath + "5.3.3.4.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.3.3.4.4"
    Task = "Ensure pam_unix includes use_authtok"
    Test = {
        $script = $commonPath + "5.3.3.4.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "5.4.1.1"
    Task = "Ensure password expiration is configured"
    Test = {
        $script = $commonPath + "5.4.1.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.1.2"
    Task = "Ensure minimum password days is configured"
    Test = {
        $script = $commonPath + "5.4.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.1.3"
    Task = "Ensure password expiration warning days is configured"
    Test = {
        $script = $commonPath + "5.4.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.1.4"
    Task = "Ensure strong password hashing algorithm is configured"
    Test = {
        $script = $commonPath + "5.4.1.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.1.5"
    Task = "Ensure inactive password lock is configured"
    Test = {
        $script = $commonPath + "5.4.1.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.1.6"
    Task = "Ensure all users last password change date is in the past"
    Test = {
        $resultScript = $scriptPath + "5.4.1.6.sh"
        $result = bash $resultScript
        if ($result -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.4.2.1"
    Task = "Ensure root is the only UID 0 account"
    Test = {
        $resultScript = $scriptPath + "5.4.2.1.sh"
        $result = bash $resultScript
        if ($result -eq "root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "5.4.2.2"
    Task = "Ensure root is the only GID 0 account"
    Test = {
        $test1 = grep "^root:" /etc/passwd | cut -f4 -d ':'
        if ($test1 -eq 0) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}
[AuditTest] @{
    Id   = "5.4.2.3"
    Task = "Ensure group root is the only GID 0 group"
    Test = {
        $script = $commonPath + "5.4.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

# MISSING RULE: 5.4.2.4 - Ensure root account access is controlled
[AuditTest] @{
    Id   = "5.4.2.5"
    Task = "Ensure root PATH Integrity"
    Test = {
        $resultScript = $scriptPath + "5.4.2.5.sh"
        $result = bash $resultScript
        if ($result -match "is not a directory") {
            return $retNonCompliant
        }
        else {
            return $retCompliant
        }
    }
}


[AuditTest] @{
    Id   = "5.4.2.6"
    Task = "Ensure root user umask is configured"
    Test = {
        $script = $commonPath + "5.4.2.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.2.7"
    Task = "Ensure system accounts do not have a valid login shell"
    Test = {
        $script = $commonPath + "5.4.2.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.2.8"
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
    Id   = "5.4.3.1"
    Task = "Ensure nologin is not listed in /etc/shells"
    Test = {
        $script = $commonPath + "5.4.3.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.3.2"
    Task = "Ensure default user shell timeout is configured"
    Test = {
        $script = $commonPath + "5.4.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "5.4.3.3"
    Task = "Ensure default user umask is configured"
    Test = {
        $script = $commonPath + "5.4.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.1.1"
    Task = "Ensure permissions on /etc/passwd are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/passwd
        if ($test1 -match "644 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "6.1.2"
    Task = "Ensure permissions on /etc/passwd are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/passwd-
        if ($test1 -match "644 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "6.1.3"
    Task = "Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
    Test = {
        $script = $commonPath + "6.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "6.2.1.1"
    Task = "Ensure journald service is enabled and active"
    Test = {
        $test1 = systemctl is-enabled rsyslog
        if ($test1 -match "enabled") {
            return @{
                Message = "Compliant"
                Status  = "True"
            }
        }
        return @{
            Message = "Not-Compliant"
            Status  = "False"
        }
    }
}

[AuditTest] @{
    Id   = "6.2.1.2"
    Task = "Ensure journald log file access is configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id   = "6.2.1.3"
    Task = "Ensure journald log file rotation is configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

# MISSING RULE: 6.2.1.4 - Ensure only one logging system is in use

[AuditTest] @{
    Id   = "6.2.2.1.1"
    Task = "Ensure systemd-journal-remote is installed"
    Test = {
        rpm -q systemd-journal-remote 2>&1 >/dev/null
        if ($?) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}


# MISSING RULE: 6.2.2.1.2 - Ensure systemd-journal-upload authentication is configured

[AuditTest] @{
    Id   = "6.2.2.1.3"
    Task = "Ensure systemd-journal-upload is enabled and active"
    Test = {
        $test1 = systemctl is-enabled systemd-journal-upload.service
        $test2 = systemctl is-active systemd-journal-upload.service
        if ($test1 -eq "enabled" -and $test2 -match "active") {
            return $retCompliant
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id   = "6.2.2.1.4"
    Task = "Ensure systemd-journal-remote service is not in use"
    Test = {
        $script = $scriptPath + "6.2.2.1.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.2.2.2"
    Task = "Ensure journald ForwardToSyslog is disabled"
    Test = {
        $script = $scriptPath + "6.2.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.2.2.3"
    Task = "Ensure journald Compress is configured"
    Test = {
        $script = $scriptPath + "6.2.2.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.2.2.4"
    Task = "Ensure journald Storage is configured"
    Test = {
        $script = $scriptPath + "6.2.2.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.2.3.1"
    Task = "Ensure rsyslog is installed"
    Test = {
        rpm -q rsyslog 2>&1 >/dev/null
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


# MISSING RULE: 6.2.3.2 - Ensure rsyslog service is enabled and active
[AuditTest] @{
    Id   = "6.2.3.3"
    Task = "Ensure journald is configured to send logs to rsyslog"
    Test = {
        rpm -q systemd-journal-remote 2>&1 >/dev/null
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "6.2.3.4"
    Task = "Ensure rsyslog log file creation mode is configured"
    Test = {
        $script = $scriptPath + "6.2.3.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 6.2.3.5 - Ensure rsyslog logging is configured
[AuditTest] @{
    Id   = "6.2.3.6"
    Task = "Ensure rsyslog is configured to send logs to a remote log host"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}


[AuditTest] @{
    Id   = "6.2.3.7"
    Task = "Ensure rsyslog is not configured to receive logs from a remote client"
    Test = {
        $script = $scriptPath + "6.2.3.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
# MISSING RULE: 6.2.3.8 - Ensure rsyslog logrotate is configured

[AuditTest] @{
    Id   = "6.2.4.1"
    Task = "Ensure access to all logfiles has been configured"
    Test = {
        $fileListAll = find /var/log -type f -ls
        $fileListFiltered = find /var/log -type f -ls | grep "\-....\-\-\-\-\-"
        if ($fileListAll.Count -eq $fileListFiltered.Count) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "6.3.1.1"
    Task = "Ensure auditd packages are installed"
    Test = {
        rpm -q auditd 2>&1 >/dev/null
        if (! $?) {
            return $retNonCompliant
        }
        rpm -q audispd-plugins 2>&1 >/dev/null
        if (! $?) {
            return $retNonCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "6.3.1.2"
    Task = "Ensure auditing for processes that start prior to auditd is enabled"
    Test = {
        $script = $scriptPath + "6.3.1.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.1.3"
    Task = "Ensure audit_backlog_limit is sufficient"
    Test = {
        $script = $scriptPath + "6.3.1.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "6.3.1.4"
    Task = "Ensure auditd service is enabled and active"
    Test = {
        $test1 = systemctl is-enabled auditd
        if ($test1 -match "enabled") {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "6.3.2.1"
    Task = "Ensure audit log storage size is configured"
    Test = {
        $script = $commonPath + "6.3.2.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.2.2"
    Task = "Ensure audit logs are not automatically deleted"
    Test = {
        $script = $commonPath + "6.3.2.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.2.3"
    Task = "Ensure system is disabled when audit logs are full"
    Test = {
        $result1 = grep space_left_action /etc/audit/auditd.conf
        $result2 = grep action_mail_acct /etc/audit/auditd.conf
        $result3 = grep -E 'admin_space_left_action\s*=\s*(halt|single)' /etc/audit/auditd.conf
        if ($result1 -match "space_left_action = email" -and $result2 -match "action_mail_acct = root" -and ($result3 -match "admin_space_left_action = halt" -or $result3 -match "admin_space_left_action = single")) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "6.3.2.4"
    Task = "Ensure system warns when audit logs are low on space"
    Test = {
        $test1 = grep -Pi -- '^\h*space_left_action\h*=\h*\w+\b' /etc/audit/auditd.conf | awk '{print $3}'
        if ($test1 -match "^(email|exec|single|halt)$") {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "6.3.3.1"
    Task = "Ensure changes to system administration scope (sudoers) is collected"
    Test = {
        $script = $commonPath + "6.3.3.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.2"
    Task = "Ensure actions as another user are always logged"
    Test = {
        $script = $commonPath + "6.3.3.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.3"
    Task = "Ensure events that modify the sudo log file are collected"
    Test = {
        $script = $commonPath + "6.3.3.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.4"
    Task = "Ensure events that modify date and time information are collected"
    Test = {
        $script = $commonPath + "6.3.3.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.5"
    Task = "Ensure events that modify the system's network environment are collected"
    Test = {
        $script = $commonPath + "6.3.3.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.6"
    Task = "Ensure use of privileged commands are collected"
    Test = {
        $script = $commonPath + "6.3.3.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.7"
    Task = "Ensure unsuccessful file access attempts are collected"
    Test = {
        $script = $commonPath + "6.3.3.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.8"
    Task = "Ensure events that modify user/group information are collected"
    Test = {
        $script = $commonPath + "6.3.3.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.9"
    Task = "Ensure discretionary access control permission modification events are collected"
    Test = {
        $script = $commonPath + "6.3.3.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.10"
    Task = "Ensure successful file system mounts are collected"
    Test = {
        $script = $commonPath + "6.3.3.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.11"
    Task = "Ensure session initiation information is collected"
    Test = {
        $script_string1 = @'
#!/usr/bin/env bash
{
    awk '/^ *-w/ &&(/\/var\/run\/utmp/ ||/\/var\/log\/wtmp/ ||/\/var\/log\/btmp/) &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
}
'@
        $script_string2 = @'
#!/usr/bin/env bash
{
     /usr/sbin/auditctl -l | awk '/^ *-w/ &&(/\/var\/run\/utmp/ ||/\/var\/log\/wtmp/ ||/\/var\/log\/btmp/) &&/ +-p *wa/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
}
'@
        $result1 = bash -c $script_string1
        $result2 = bash -c $script_string2
        if ($result1 -match "-w /var/run/utmp -p wa -k session" -and $result1 -match "-w /var/log/wtmp -p wa -k session" -and $result1 -match "-w /var/log/btmp -p wa -k session" -and
            $result2 -match "-w /var/run/utmp -p wa -k session" -and $result2 -match "-w /var/log/wtmp -p wa -k session" -and $result2 -match "-w /var/log/btmp -p wa -k session") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}



[AuditTest] @{
    Id   = "6.3.3.12"
    Task = "Ensure login and logout events are collected"
    Test = {
        $script = $commonPath + "6.3.3.12.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.13"
    Task = "Ensure file deletion events by users are collected"
    Test = {
        $script = $commonPath + "6.3.3.13.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.14"
    Task = "Ensure events that modify the system's Mandatory Access Controls are collected"
    Test = {
        $script = $commonPath + "6.3.3.14.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.15"
    Task = "Ensure successful and unsuccessful attempts to use the chcon command are recorded"
    Test = {
        $script = $commonPath + "6.3.3.15.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.16"
    Task = "Ensure successful and unsuccessful attempts to use the setfacl command are recorded"
    Test = {
        $script = $commonPath + "6.3.3.16.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.17"
    Task = "Ensure successful and unsuccessful attempts to use the chacl command are recorded"
    Test = {
        $script = $commonPath + "6.3.3.17.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.18"
    Task = "Ensure successful and unsuccessful attempts to use the usermod command are recorded"
    Test = {
        $script = $commonPath + "6.3.3.18.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.19"
    Task = "Ensure kernel module loading unloading and modification is collected"
    Test = {
        $script = $commonPath + "6.3.3.19.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.3.20"
    Task = "Ensure the audit configuration is immutable"
    Test = {
        $result1 = grep -Ph -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules | tail -1
        if ($result1 -match "-e 2") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "6.3.3.21"
    Task = "Ensure the running and on disk configuration is the same"
    Test = {
        $result1 = augenrules --check
        if ($result1 -match "/usr/sbin/augenrules: No change") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "6.3.4.1"
    Task = "Ensure the audit log file directory mode is configured"
    Test = {
        $script = $scriptPath + "6.3.4.1.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.4.2"
    Task = "Ensure audit log files mode is configured"
    Test = {
        $script = $scriptPath + "6.3.4.2.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.4.3"
    Task = "Ensure audit log files owner is configured"
    Test = {
        $script = $scriptPath + "6.3.4.3.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.4.4"
    Task = "Ensure audit log files group owner is configured"
    Test = {
        $script = $scriptPath + "6.3.4.4.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.4.5"
    Task = "Ensure audit configuration files mode is configured"
    Test = {
        $script = $commonPath + "6.3.4.5.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.4.6"
    Task = "Ensure audit configuration files owner is configured"
    Test = {
        $script = $commonPath + "6.3.4.6.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.4.7"
    Task = "Ensure audit configuration files group owner is configured"
    Test = {
        $script = $commonPath + "6.3.4.7.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.4.8"
    Task = "Ensure audit tools mode is configured"
    Test = {
        $script = $commonPath + "6.3.4.8.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}
[AuditTest] @{
    Id   = "6.3.4.9"
    Task = "Ensure audit tools owner is configured"
    Test = {
        $script = $commonPath + "6.3.4.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "6.3.4.10"
    Task = "Ensure audit tools group owner is configured"
    Test = {
        $test1 = stat -Lc '%G' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk '$1 != "root" {print}'
        if ($test1 -eq $null) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "7.1.1"
    Task = "Ensure permissions on /etc/passwd are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/passwd-
        if ($test1 -match "644 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "7.1.2"
    Task = "Ensure permissions on /etc/passwd- are configured"
    Test = {
        $test1 = stat -c '%#a' /etc/passwd- | grep -q "0644"
        if ($?) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "7.1.3"
    Task = "Ensure permissions on /etc/group are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/group
        if ($test1 -match "644 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.1.4"
    Task = "Ensure permissions on /etc/group- are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/group-
        if ($test1 -match "644 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.1.5"
    Task = "Ensure permissions on /etc/shadow are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/shadow
        if ($test1 -match "0 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.1.6"
    Task = "Ensure permissions on /etc/shadow- are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/shadow-
        if ($test1 -match "0 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.1.7"
    Task = "Ensure permissions on /etc/gshadow are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/gshadow
        if ($test1 -match "0 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.1.8"
    Task = "Ensure permissions on /etc/gshadow- are configured"
    Test = {
        $test1 = stat -Lc "%n %a %u/%U %g/%G" /etc/gshadow-
        if ($test1 -match "0 0/root 0/root") {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.1.9"
    Task = "Ensure permissions on /etc/shells are configured"
    Test = {
        $script = $commonPath + "7.1.9.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id   = "7.1.10"
    Task = "Ensure permissions on /etc/security/opasswd are configured"
    Test = {
        $script = $commonPath + "7.1.10.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "7.1.11"
    Task = "Ensure world writable files and directories are secured"
    Test = {
        #$partitions = mapfile -t partitions < (sudo fdisk -l | grep -o '/dev/[^ ]*')
        #$test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
        $script = $commonPath + "7.1.11.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id   = "7.1.12"
    Task = "Ensure no files or directories without an owner and a group exist"
    Test = {
        $script = $commonPath + "7.1.12.sh"
        bash $script
        if ($?) {
            return $retCompliant
        }
        return $retNonCompliant
    }
} 

[AuditTest] @{
    Id   = "7.1.13"
    Task = "Ensure SUID and SGID files are reviewed"
    Test = {
        $test1 = df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000
        $message = ""
        foreach ($line in $test1) {
            $message += "<br>$line"
        }
        return @{
            Message = "Please review following list of files: $($message)"
            Status  = "None"
        }
    }
}

[AuditTest] @{
    Id   = "7.2.1"
    Task = "Ensure accounts in /etc/passwd use shadowed passwords"
    Test = {
        $resultScript = $scriptPath + "7.2.1.sh"
        $result = bash $resultScript
        if ($result -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.2.2"
    Task = "Ensure /etc/shadow password fields are not empty"
    Test = {
        $resultScript = $scriptPath + "7.2.2.sh"
        $result = bash $resultScript
        if ($result -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.2.3"
    Task = "Ensure all groups in /etc/passwd exist in /etc/group"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        if [ $? -ne 0 ]; then
            echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
        fi
    done
}
'@
        $script = bash -c $script_string
        if ($script -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.2.4"
    Task = "Ensure no duplicate UIDs exist"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
        [ -z "$x" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
            echo "Duplicate UID ($2): $users"
        fi
    done
}
'@
        $script = bash -c $script_string
        if ($script -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.2.5"
    Task = "Ensure no duplicate GIDs exist"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
        echo "Duplicate GID ($x) in /etc/group"
    done
}
'@
        $script = bash -c $script_string
        if ($script -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.2.6"
    Task = "Ensure no duplicate user names exist"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r x; do
        echo "Duplicate login name $x in /etc/passwd"
    done
}
'@
        $script = bash -c $script_string
        if ($script -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{
    Id   = "7.2.7"
    Task = "Ensure no duplicate group names exist"
    Test = {
        $script_string = @'
#!/usr/bin/env bash
{
    cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do
        echo "Duplicate group name $x in /etc/group"
    done
}
'@
        $script = bash -c $script_string
        if ($script -eq $null) {
            return $retCompliant
        }
        else {
            return $retNonCompliant
        }
    }
}


[AuditTest] @{ # in CIS it's automated, but in Excelsheet it's manual
    Id   = "7.2.8"
    Task = "Ensure local interactive user home directories are configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id   = "7.2.9"
    Task = "Ensure local interactive user dot files access is configured"
    Test = {
        return $retNonCompliantManualReviewRequired
    }
}

