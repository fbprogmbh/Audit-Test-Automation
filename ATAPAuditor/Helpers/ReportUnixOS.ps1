[SystemInformation]@{
    SoftwareInformation = [SoftwareInformation]@{
        Hostname = hostname
        OperatingSystem = (Get-Content /etc/os-release | Select-String -Pattern '^PRETTY_NAME=\"(.*)\"$').Matches.Groups[1].Value
        BuildNumber = 'Version {0} (Build {1}.{2})' -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR
        InstallationLanguage = (($(locale) | Where-Object { $_ -match "LANG=" }) -split '=')[1]
        SystemUptime = uptime -p
        OSArchitecture = dpkg --print-architecture
        KernelVersion = uname -r
    }
    HardwareInformation = [HardwareInformation]@{
        BIOSVersion = dmidecode -s bios-version
        SystemSKU = (dmidecode -t system)[12] | cut -d ':' -f 2 | xargs
        SystemSerialnumber = (dmidecode -t system)[9] | cut -d ':' -f 2 | xargs
        SystemManufacturer = (dmidecode -t system)[6] | cut -d ':' -f 2 | xargs
        SystemModel = dmidecode -s system-product-name
        FreeDiskSpace = "{0:N1} GB" -f ((Get-PSDrive | Where-Object { $_.Name -eq '/' }).Free / 1GB)
        FreePhysicalMemory = "{0:N1} GB" -f (( -split (Get-Content /proc/meminfo | Where-Object { $_ -match 'MemFree:' }))[1] / 1MB)
    }
}
