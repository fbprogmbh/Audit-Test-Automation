[AuditTest] @{
    Id = "1.1.1.1"
    Task = "Ensure mounting of cramfs filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v cramfs | grep -E '(cramfs|install)'
        $result2 = lsmod | grep cramfs
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
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
    Id = "1.1.1.2"
    Task = "Ensure mounting of freevxfs filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v freevxfs | grep -E '(freevxfs|install)'
        $result2 = lsmod | grep freevxfs
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
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
    Id = "1.1.1.3"
    Task = "Ensure mounting of jffs2 filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v jffs2 | grep -E '(jffs2|install)'
        $result2 = lsmod | grep jffs2
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
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
    Id = "1.1.1.4"
    Task = "Ensure mounting of hfs filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v hfs | grep -E '(hfs|install)'
        $result2 = lsmod | grep hfs
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
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
    Id = "1.1.1.5"
    Task = "Ensure mounting of hfsplus filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v hfsplus | grep -E '(hfsplus|install)'
        $result2 = lsmod | grep hfsplus
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
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
    Id = "1.1.1.6"
    Task = "Ensure mounting of squashfs filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v squashfs | grep -E '(squashfs|install)'
        $result2 = lsmod | grep squashfs
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
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
    Id = "1.1.1.7"
    Task = "Ensure mounting of udf filesystetms is disabled"
    Test = {
        $result1 = modprobe -n -v udf | grep -E '(udf|install)'
        $result2 = lsmod | grep udf
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
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
    Id = "1.1.2"
    Task = "Ensure /tmp is configured"
    Test = {
        $result1 = modprobe -n -v udf | grep -E '(udf|install)'
        $result2 = lsmod | grep udf
        
        if($result1 -match "install /bin/true" -and $result2 -eq $null){
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
    Id = "1.1.3"
    Task = "Ensure nodev option set on /tmp partition"
    Test = {
        $result = findmnt -n /tmp | grep -v nodev

        if($result -eq $null){
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
    Id = "1.1.4"
    Task = "Ensure nosuid option set on /tmp partition"
    Test = {
        $result = findmnt -n /tmp | grep -v nosuid
        
        if($result -eq $null){
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
    Id = "1.1.5"
    Task = "Ensure noexec option set on /tmp partition"
    Test = {
        $result = findmnt -n /tmp | grep -v noexec
        
        if($result -eq $null){
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
    Id = "1.1.6"
    Task = "Ensure /dev/shm is configured"
    Test = {
        $result = findmnt -n /dev/shm
        
        if($result -match "/dev/shm tmpfs tmpfs rw,nosuid,nodev,noexec"){
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
    Id = "1.1.7"
    Task = "Ensure nodev option set on /dev/shm partition"
    Test = {
        $result = findmnt -n /dev/shm | grep -v nodev
        
        if($result -eq $null){
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
    Id = "1.1.8"
    Task = "Ensure nosuid option set on /dev/shm partition"
    Test = {
        $result = findnmt -n /dev/shm | grep -v nosuid
        
        if($result -eq $null){
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
    Id = "1.1.9"
    Task = "Ensure noexec option set on /dev/shm partition"
    Test = {
        $result = findmnt -n /dev/shm | grep -v noexec
        
        if($result -eq $null){
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
    Id = "1.1.10"
    Task = "Ensure separate partition exists for /var"
    Test = {
        $result = findmnt /var
        
        if($result -match "/var <device> <fstype> rw,relatime,attr2,inode64,noquota"){
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
    Id = "1.1.11"
    Task = "Ensure separate partition exists for /var/tmp"
    Test = {
        $result = findmnt /var/tmp
        
        if($result -match "/var <device> <fstype> rw,relatime,attr2,inode64,noquota"){
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