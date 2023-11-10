$parentPath = Split-Path -Parent -Path $PSScriptRoot
$rcTrue = "True"
$rcCompliant = "Compliant"
$retCompliant = @{
    Message = $rcCompliant
    Status = $rcTrue
}
$rcFalse = "False"
$rcNonCompliant = "Non-Compliant"
$retNonCompliant = @{
    Message = $rcNonCompliant
    Status = $rcFalse
}

### Chapter 1 - Initial Setup

[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure mounting of squashfs filesystems is disabled"
    Test = {
        $result1 = modprobe -n -v squashfs | grep -E '(suqashfs|install)'
        $result2 = lsmod | grep squashfs
        if ($result1 -match "install /bin/true" && $result2 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.1.2"
    Task = "Ensure mounting of udf filesystems is disabled"
    Test = {
        $result1 = modprobe -n -v udf | grep -E '(udf|install)'
        $result2 = lsmod | grep udf
        if ($result1 -match "install /bin/true" && $result2 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.1.3"
    Task = "Ensure mounting of FAT filesystems is disabled"
    Test = {
        $result1 = modprobe -n -v fat | grep -E '(fat|install)'
        $result2 = lsmod | grep udf
        $result3 = modprobe -n -v vfat | grep -E '(vfat|install)'
        $result4 = lsmod | grep udf
        $result5 = modprobe -n -v msdos | grep -E '(msdos|install)'
        $result6 = lsmod | grep udf
        if ($result1 -match "install /bin/true" && $result2 -eq $null && $result3 -match "install /bin/true" && $result4 -eq $null && $result5 -match "install /bin/true" && $result6 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.2"
    Task = "Ensure /tmp is configured"
    Test = {
        $result1 = mount | grep -E '\s/tmp\s'
        if ($result1 -match "/tmp") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.3"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/tmp\s' | grep -v noexec
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.4"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/tmp\s' | grep -v nodev
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.5"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/tmp\s' | grep -v nosuid
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.6"
    Task = "Ensure /dev/shm is configured"
    Test = {
        $result1 = mount | grep -E '\s/dev/shm\s'
        $result2 = grep -E '\s/dev/shm\s' /etc/fstab
        if ($result1 -ne $null && $result2 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.7"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $result1 = mount | grep -E '\s/dev/shm\s' | grep -v noexec
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.8"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $result1 = mount | grep -E '\s/dev/shm\s' | grep -v nodev
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.9"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $result1 = mount | grep -E '\s/dev/shm\s' | grep -v nosuid
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.10"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result1 = mount | grep -E '\s/var\s'
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.11"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result1 = mount | grep /var/tmp
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.12"
    Task = "Ensure noexec option set on /var/tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/var/tmp\s' | grep -v noexec
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.13"
    Task = "Ensure nodev option set on /var/tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/var/tmp\s' | grep -v nodev
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.14"
    Task = "Ensure nosuid option set on /var/tmp partition"
    Test = {
        $result1 = mount | grep -E '\s/var/tmp\s' | grep -v nosuid
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.15"
    Task = "Ensure separate partition exists for /var/log"
    Test = {
        $result1 = mount | grep -E '\s/var/log\s'
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.16"
    Task = "Ensure separate partition exists for /var/log/audit"
    Test = {
        $result1 = mount | grep /var/log/audit
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.17"
    Task = "Ensure separate partition exists for /home"
    Test = {
        $result1 = mount | grep /home
        if ($result1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.18"
    Task = "Ensure nodev option set on /home partition"
    Test = {
        $result1 = mount | grep -E '\s/home\s' | grep -v nodev
        if ($result1 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.19"
    Task = "Ensure noexec option set on removable media partitions"
    Test = {
        $path = $parentPath+"/Helpers/ShellScripts/CIS-SUSE15-1.1.19_through_1.1.21.sh"
        $result = bash $path
        foreach($line in $result){
            if(!($line -match "noexec")){
                return $retNonCompliant
            }
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "1.1.20"
    Task = "Ensure nodev option set on removable media partitions"
    Test = {
        $path = $parentPath+"/Helpers/ShellScripts/CIS-SUSE15-1.1.19_through_1.1.21.sh"
        $result = bash $path
        foreach($line in $result){
            if(!($line -match "nodev")){
                return $retNonCompliant
            }
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "1.1.21"
    Task = "Ensure nosuid option set on removable media partitions"
    Test = {
        $path = $parentPath+"/Helpers/ShellScripts/CIS-SUSE15-1.1.19_through_1.1.21.sh"
        $result = bash $path
        foreach($line in $result){
            if(!($line -match "nosuid")){
                return $retNonCompliant
            }
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "1.1.22"
    Task = "Ensure sticky bit is set on all world-writable directories"
    Test = {
        $result = df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
        if ($result -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.1.23"
    Task = "Disable Automounting"
    Test = {
        $result = systemctl is-enabled autofs
        if ($result -match "enabled") {
            return $retNonCompliant
        } else {
            return $retCompliant
        }
    }
}

# 1.2.1 TODO - brauche suse15 zur implementierung
# 1.2.2 TODO - s.o.

[AuditTest] @{
    Id = "1.2.3"
    Task = "Ensure gpgcheck is globally activated"
    Test = {
        $result = grep ^\s*gpgcheck /etc/zypp/zypp.conf
        if ($result -match "gpgcheck=1") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.3.1"
    Task = "Ensure sudo is installed"
    Test = {
        $result = rpm -q sudo
        if ($result -match "sudo-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.3.2"
    Task = "Ensure sudo is installed"
    Test = {
        $result = grep -Ei '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers /etc/sudoers.d/*
        if ($result -match "Defaults user_pty") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.3.3"
    Task = "Ensure sudo log file exists"
    Test = {
        $result = grep -Ei '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(")?[^#;]+(")?' /etc/sudoers /etc/sudoers.d/*
        if ($result -match "Defaults logfile=") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.4.1"
    Task = "Ensure aide is installed"
    Test = {
        $result = rpm -q aide
        if ($result -match "aide-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.4.2"
    Task = "Ensure filesystem integrity is regularly checked"
    Test = {
        $result1 = crontab -u root -l | grep aide
        $result2 = grep -r aide /etc/cron.* /etc/crontab
        if ($result1 -ne $null || $result2 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.5.1"
    Task = "Ensure bootloader password is set"
    Test = {
        $result1 = grep "^\s*set superusers" /boot/grub2/grub.cfg
        $result2 = grep "^\s*password" /boot/grub2/grub.cfg
        if ($result1 -match "set superusers=" && $result2 -match "password_pbkdf2 ") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.5.2"
    Task = "Ensure permissions on bootloader config are configured"
    Test = {
        $result = stat /boot/grub2/grub.cfg | grep "Uid: "
        $result = $result | cut -d '(' -f 2
        $result = $result | cut -d '/' -f 1
        if($result -eq "0400" -or $result[1] -le 4){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.5.3"
    Task = "Ensure authentication required for single user mode"
    Test = {
        $result1 = grep /systemd-sulogin-shell /usr/lib/systemdm/system/rescue.service
        $result2 = grep /systemd-sulogin-shell /usr/lib/systemdm/system/rescue.service
        if($result1 -ne $null -and $result2 -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.1"
    Task = "Ensure core dumps are restricted"
    Test = {
        $result1 = grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf
        $result2 = sysctl fs.suid_dumpable
        $result3 = grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "hard core 0" -and $result2 -match "fs.suid_dumpable = 0" -and $result3 -match "fs.suid_dumpable = 0") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# 1.6.2 implemented for journalctl only
[AuditTest] @{
    Id = "1.6.2"
    Task = "Ensure XD/NX support is enabled"
    Test = {
        $result1 = journalctl | grep 'protection: active'
        if($result1 -match "protection: active") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.3"
    Task = "Ensure address space layout randomization (ASLR) is enabled"
    Test = {
        $result1 = sysctl kernel.randomize_va_space
        $result2 = grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "kernel.randomize_va_space = 2" -and $result2 -match "kernel.randomize_va_space = 2") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.6.4"
    Task = "Ensure prelink is disabled"
    Test = {
        $result1 = rpm -q prelink
        if($result1 -match "package prelink is not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1.1"
    Task = "Ensure AppArmor is installed"
    Test = {
        $result1 = rpm -q apparmor-docs apparmor-parser apparmor-profiles apparmor-utils libapparmor1
        if($result1 -ne $null -or $result2 -ne $null) {
            return $retNonCompliant
        } else {
            return $retCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1.2"
    Task = "Ensure AppArmor is enabled in the bootloader configuration"
    Test = {
        $result1 = grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "apparmor=1"
        $result2 = grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "security=apparmor"
        if($result1 -match "apparmor-docs-" -and $result1 -match "apparmor-parser-" -and $result1 -match "apparmor-profiles-" -and $result1 -match "apparmor-utils-" -and $result1 -match "libapparmor1-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1.3"
    Task = "Ensure all AppArmor Profiles are in enforce or complain mode"
    Test = {
        $profileMode1 = apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        $profileMode3 = apparmor_status | grep profiles | sed '3!d' | cut -d ' ' -f 1
        $result = expr $profileMode3 + $profileMode2
        $unconfinedProcesses = apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1
        if ($result -eq $profileMode1 -and $unconfinedProcesses -eq 0) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.7.1.4"
    Task = "Ensure all AppArmor Profiles are enforcing"
    Test = {
        $profileMode1 = apparmor_status | grep profiles | sed '1!d' | cut -d ' ' -f 1
        $profileMode2 = apparmor_status | grep profiles | sed '2!d' | cut -d ' ' -f 1
        
        $unconfinedProcesses = apparmor_status | grep processes | sed '4!d' | cut -d ' ' -f 1

        if($profileMode1 -eq $profileMode2 -and $unconfinedProcesses -eq 0){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.1"
    Task = "Ensure message of the day is configured properly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.2"
    Task = "Ensure local login warning is configured peoperly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.3"
    Task = "Ensure remote login warning banner is configured properly"
    Test = {
        $result = grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.4"
    Task = "Ensure permissions on /etc/motd are configured"
    Test = {
        $result = stat -L /etc/motd | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        if($result -eq $null -or $result -match "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.5"
    Task = "Ensure permissions on /etc/issue are configured"
    Test = {
        $result = stat -L /etc/issue | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        if($result -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.8.1.6"
    Task = "Ensure permissions on /etc/issue.net are configured"
    Test = {
        $result = stat -L /etc/issue.net | grep "Access:\s*(0644/-rw-r--r--)\s*Uid:\s*(\s*0/\s*root)\s*Gid:\s*(\s*0/\s*root)"
        if($result -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.9"
    Task = "Ensure updates, patches, and additional security software are installed"
    Test = {
        $output = zypper list-updates
        $output = $?
        if($output -match "True"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "1.10"
    Task = "Ensure GDM is removed or login is configured"
    Test = {
        $result = rpm -q gdm
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

### Chapter 2 - Services

[AuditTest] @{
    Id = "2.1.1"
    Task = "Ensure xinetd is not installed"
    Test = {
        $result = rpm -q xinetd
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.1.1"
    Task = "Ensure time synchronization is in use"
    Test = {
        $result = rpm -q chrony
        if($result -match "chrony-"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.1.2"
    Task = "Ensure systemd-timesyncd is configured"
    Test = {
        $result = systemctl is-enabled systemd-timesyncd.service
        if($result -match "enabled"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.1.3"
    Task = "Ensure chrony is configured"
    Test = {
        $result1 = grep -E "^(server|pool)" /etc/chrony.conf
        $result2 = grep ^OPTIONS /etc/sysconfig/chronyd
        if($result1 -match "server " && $result2 -match "-u chrony"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.2"
    Task = "Ensure X11 Server components are not installed"
    Test = {
        $result = rpm -qa xorg-x11-server*
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.4"
    Task = "Ensure CUPS is not installed"
    Test = {
        $result = rpm -q cups
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.5"
    Task = "Ensure DHCP Server is not installed"
    Test = {
        $result = rpm -q dhcp
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.6"
    Task = "Ensure LDAP server is not installed"
    Test = {
        $result = rpm -q openldap2
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.7"
    Task = "Ensure nfs-utils is not installed or the nfs-server service is masked"
    Test = {
        $result1 = rpm -q nfs-utils
        $result2 = rpm -q nfs-kernel-server
        if($result1 -match "not installed" && $result2 -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.8"
    Task = "Ensure rpcbind is not installed or the rpcbind services are masked"
    Test = {
        $result = rpm -q rpcbind
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.9"
    Task = "Ensure DNS Server is not installed"
    Test = {
        $result = rpm -q bind
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.10"
    Task = "Ensure FTP Server is not installed"
    Test = {
        $result = rpm -q vsftpd
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.11"
    Task = "Ensure HTTP Server is not installed"
    Test = {
        $result = rpm -q apache2
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.12"
    Task = "Ensure HTTP Server is not installed"
    Test = {
        $result = rpm -q dovecot
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.13"
    Task = "Ensure Samba is not installed"
    Test = {
        $result = rpm -q samba
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.14"
    Task = "Ensure HTTP Proxy Server is not installed"
    Test = {
        $result = rpm -q squid
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.15"
    Task = "Ensure net-snmp is not installed"
    Test = {
        $result = rpm -q net-snmp
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.16"
    Task = "Ensure mail transfer agent is configured for local-only mode"
    Test = {
        $result = ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.17"
    Task = "Ensure rsync is not installed or the rsyncd service is masked"
    Test = {
        $result = rpm -q rsync
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.18"
    Task = "Ensure NIS server is not installed"
    Test = {
        $result = rpm -q ypserv
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.2.19"
    Task = "Ensure telnet-server is not installed"
    Test = {
        $result = rpm -q telnet-server
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.1"
    Task = "Ensure NIS Client is not installed"
    Test = {
        $result = rpm -q ypbind
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.2"
    Task = "Ensure rsh client is not installed"
    Test = {
        $result = rpm -q rsh
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.3"
    Task = "Ensure talk client is not installed"
    Test = {
        $result = rpm -q talk
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.4"
    Task = "Ensure telnet client is not installed"
    Test = {
        $result = rpm -q telnet
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "2.3.5"
    Task = "Ensure LDAP client is not installed"
    Test = {
        $result = rpm -q openldap2-clients
        if($result -match "not installed"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# 2.4 nicht umsetzbar, manuell zu reviewen 
[AuditTest] @{
    Id = "2.4"
    Task = "Ensure nonessential services are removed or masked"
    Test = {
        return @{
            Message = "Manual review required"
            Status = $rcFalse
        }
    }
}

## Chapter 3 Network Configuration

# sysctl wird ignoriert
[AuditTest] @{
    Id = "3.1.1"
    Task = "Disable IPv6"
    Test = {
        $result = grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disable=1
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.1.2"
    Task = "Ensure wireless interfaces are disabled"
    Test = {
        $result = ip link show up
        if($result -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# Pruefung nur fuer IPv4
[AuditTest] @{
    Id = "3.1.2"
    Task = "Ensure IP forwarding is disabled"
    Test = {
        $result1 = sysctl net.ipv4.ip_forward
        $result2 = grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
        if($result1 -match "net.ipv4.ip_forward = 0" && $result2 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.2.2"
    Task = "Ensure packet redirect sending is disabled"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.send_redirects
        $result2 = sysctl net.ipv4.conf.default.send_redirects
        $result3 = grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.send_redirects = 0" && $result2 -match "net.ipv4.conf.default.send_redirects = 0" && $result3 -match "net.ipv4.conf.all.send_redirects = 0" && $result4 -match "net.ipv4.conf.default.send_redirects= 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# vorest nur IPv4
[AuditTest] @{
    Id = "3.3.1"
    Task = "Ensure source routed packets are not accepted"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.accept_source_route
        $result2 = sysctl net.ipv4.conf.default.accept_source_route
        $result3 = grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.accept_source_route = 0" && $result2 -match "net.ipv4.conf.default.accept_source_route = 0" && $result3 -match "net.ipv4.conf.all.accept_source_route= 0" && $result4 -match "net.ipv4.conf.default.accept_source_route= 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.2"
    Task = "Ensure ICMP redirects are not accepted"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.accept_redirects
        $result2 = sysctl net.ipv4.conf.default.accept_redirects
        $result3 = grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.accept_redirects = 0" && $result2 -match "net.ipv4.conf.default.accept_redirects = 0" && $result3 -match "net.ipv4.conf.all.accept_redirects= 0" && $result4 -match "net.ipv4.conf.default.accept_redirects= 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.3"
    Task = "Ensure secure ICMP redirects are not accepted"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.secure_redirects
        $result2 = sysctl net.ipv4.conf.default.accept_redirects
        $result3 = grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.accept_redirects = 0" && $result2 -match "net.ipv4.conf.default.accept_redirects = 0" && $result3 -match "net.ipv4.conf.all.accept_redirects= 0" && $result4 -match "net.ipv4.conf.default.accept_redirects= 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.4"
    Task = "Ensure suspicious packets are logged"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.log_martians
        $result2 = sysctl net.ipv4.conf.default.log_martians
        $result3 = grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.log_martians = 1" && $result2 -match "net.ipv4.conf.default.log_martians = 1" && $result3 -match "net.ipv4.conf.all.log_martians = 1" && $result4 -match "net.ipv4.conf.default.log_martians = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.5"
    Task = "Ensure broadcast ICMP requests are ignored"
    Test = {
        $result1 = sysctl net.ipv4.icmp_echo_ignore_broadcasts
        $result2 = grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.icmp_echo_ignore_broadcasts = 1" && $result2 -match "net.ipv4.icmp_echo_ignore_broadcasts = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.6"
    Task = "Ensure bogus ICMP responses are ignored"
    Test = {
        $result1 = sysctl net.ipv4.icmp_ignore_bogus_error_responses
        $result2 = grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.icmp_ignore_bogus_error_responses = 1" && $result2 -match "net.ipv4.icmp_ignore_bogus_error_responses = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.7"
    Task = "Ensure Reverse Path Filtering is enabled"
    Test = {
        $result1 = sysctl net.ipv4.conf.all.rp_filter
        $result2 = sysctl net.ipv4.conf.default.rp_filter
        $result3 = grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.conf.all.rp_filter = 1" && $result2 -match "net.ipv4.conf.default.rp_filter = 1" && $result3 -match "net.ipv4.conf.all.rp_filter = 1" && $result4 -match "net.ipv4.conf.default.rp_filter = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.8"
    Task = "Ensure TCP SYN Cookies is enabled"
    Test = {
        $result1 = sysctl net.ipv4.tcp_syncookies
        $result2 = grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv4.tcp_syncookies = 1" && $result2 -match "net.ipv4.tcp_syncookies = 1"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.3.9"
    Task = "Ensure IPv6 router advertisements are not accepted"
    Test = {
        $result1 = sysctl net.ipv6.conf.all.accept_ra
        $result2 = sysctl net.ipv6.conf.default.accept_ra
        $result3 = grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
        $result4 = grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
        if($result1 -match "net.ipv6.conf.all.accept_ra = 0" && $result2 -match "net.ipv6.conf.default.accept_ra = 0" && $result3 -match "net.ipv6.conf.all.accept_ra = 0" && $result4 -match "net.ipv6.conf.default.accept_ra = 0"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.4.1"
    Task = "Ensure TCP SYN Cookies is enabled"
    Test = {
        $result1 = modprobe -n -v dccp
        $result2 = lsmod | grep dccp
        if($result1 -match "install /bin/true" && $result2 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.4.2"
    Task = "Ensure SCTP is disabled"
    Test = {
        $result1 = modprobe -n -v sctp
        $result2 = lsmod | grep sctp
        if($result1 -match "install /bin/true" && $result2 -eq $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.1"
    Task = "Ensure FirewallD is installed"
    Test = {
        $result = rpm -q firewalld iptables
        if($result -match "firewalld-" && $result -match "iptables-"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.2"
    Task = "Ensure nftables is not installed or stopped and masked"
    Test = {
        $result1 = rpm -q nftables
        $result21 = systemctl status nftables | grep "Active: " | grep -v "active (running) "
        $result22 = systemctl is-enabled nftables
        if($result1 -match "not installed" || ($result21 -eq $null && $result22 -match "masked")){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.3"
    Task = "Ensure firewalld service is enabled and running"
    Test = {
        $result1 = systemctl is-enabled firewalld
        $result2 = firewall-cmd --state
        if($result1 -match "enabled" && $result2 -match "running"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.4"
    Task = "Ensure default zone is set"
    Test = {
        $result = firewall-cmd --get-default-zone
        if($result -ne $null){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.5"
    Task = "Ensure network interfaces are assigned to appropriate zone"
    Test = {
        return @{
            Message = "Manual review required"
            Status = $rcFalse
        }
    }
}

[AuditTest] @{
    Id = "3.5.1.6"
    Task = "Ensure unnecessary services and ports are not accepted"
    Test = {
        return @{
            Message = "Manual review required"
            Status = $rcFalse
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.1"
    Task = "Ensure nftables is installed"
    Test = {
        $result = rpm -q nftables
        if($result -match "nftables-"){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.2"
    Task = "Ensure firewalld is not installed or stopped and masked"
    Test = {
        $result1 = rpm -q firewalld
        $result21 = systemctl status firewalld | grep "Active: " | grep -v "active (running) "
        $result22 = systemctl is-enabled firewalld
        if($result1 -match "not installed" || ($result21 -eq $null && $result22 -match "masked")){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.3"
    Task = "Ensure iptables are flushed"
    Test = {
        return @{
            Message = "Manual review required"
            Status = $rcFalse
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.4"
    Task = "Ensure a table exists"
    Test = {
        $result = nft list tables
        if($result -match "table inet filter") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.5"
    Task = "Ensure base chain exist"
    Test = {
        $result1 = nft list ruleset | grep 'hook input'
        $result2 = nft list ruleset | grep 'hook forward'
        $result3 = nft list ruleset | grep 'hook output'
        if($result1 -match "type filter hook input priority 0;" && $result2 -match "type filter hook forward priority 0;" && $result3 -match "type filter hook output priority 0;") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.6"
    Task = "Ensure loopback traffic is configured"
    Test = {
        $result1 = nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'
        $result2 = nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'
        if($result1 -match "iif ""lo"" accept" && $result2 -match "ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.7"
    Task = "Ensure outbound and established connections are configured"
    Test = {
        return @{
            Message = "Manual review required"
            Status = $rcFalse
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.8"
    Task = "Ensure default deny firewall policy"
    Test = {
        $result1 = nft list ruleset | grep 'hook input'
        $result2 = nft list ruleset | grep 'hook forward'
        $result3 = nft list ruleset | grep 'hook output'
        if($result1 -match "type filter hook input priority 0; policy drop;" && $result2 -match "type filter hook forward priority 0; policy drop;" && $result3 -match "type filter hook output priority 0; policy drop;") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.9"
    Task = "Ensure nftables service is enabled"
    Test = {
        $result = systemctl is-enabled nftables
        if($result -match "enabled") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.2.10"
    Task = "Ensure nftables rules are permanent"
    Test = {
        return @{
            Message = "Manual review required"
            Status = $rcFalse
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.1.1"
    Task = "Ensure iptables package is installed"
    Test = {
        $result = rpm -q iptables
        if($result -match "iptables-") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.1.2"
    Task = "Ensure nftables is not installed"
    Test = {
        $result = rpm -q nftables
        if($result -match "not installed") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.1.3"
    Task = "Ensure firewalld is not installed or stopped and masked"
    Test = {
        $result1 = rpm -q firewalld
        $result21 = systemctl status firewalld | grep "Active: " | grep -v "active (running) "
        $result22 = systemctl is-enabled firewalld
        if($result1 -match "not installed" || ($result21 -eq $null && $result22 -match "masked")){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.2.1"
    Task = "Ensure default deny firewall policy"
    Test = {
        $output = iptables -L
        $test11 = $output -match "DROP" | grep "Chain INPUT (policy DROP)"
        $result11 = $?
        $test12 = $output -match "REJECT" | grep "Chain INPUT (policy REJECT)"
        $result12 = $?
        $test21 = $output -match "DROP" | grep "Chain FORWARD (policy DROP)"
        $result21 = $?
        $test22 = $output -match "REJECT" | grep "Chain FORWARD (policy REJECT)"
        $result22 = $?
        $test31 = $output -match "DROP" | grep "Chain OUTPUT (policy DROP)"
        $result31 = $?
        $test32 = $output -match "REJECT" | grep "Chain OUTPUT (policy REJECT)"
        $result32 = $?
        if(($result11 -match "True" || $result12 -match "True") && ($result21 -match "True" || $result22 -match "True") && ($result31 -match "True" || $result32 -match "True")){
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.2.2"
    Task = "Ensure iptables loopback traffic is configured"
    Test = {
        $test1 = iptables -L INPUT -v -n | grep "Chain\s*INPUT\s*(policy\s*DROP"
        $test2 = iptables -L OUTPUT -v -n | grep "Chain\s*OUTPUT\s*(policy\s*DROP"
        if($test1 -ne $null -and $test2 -ne $null){
            return $retCompliant
        }
        return $retNonCompliant
    }
}

[AuditTest] @{
    Id = "3.5.3.2.3"
    Task = "Ensure outbound and established connections are configured"
    Test = {
        return @{
            Message = "Manual review required"
            Status = $rcFalse
        }
    }
}

[AuditTest] @{
    Id = "3.5.3.2.4"
    Task = "Ensure firewall rules exist for all open ports"
    Test = {
        return @{
            Message = "Manual review required"
            Status = $rcFalse
        }
    }
}