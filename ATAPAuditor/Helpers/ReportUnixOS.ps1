[SystemInformationUnix]@{
    SoftwareInformation = [SoftwareInformationUnix]@{
        Hostname = hostname
        OperatingSystem = (Get-Content /etc/os-release | Select-String -Pattern '^PRETTY_NAME=\"(.*)\"$').Matches.Groups[1].Value
        LicenseStatus = $lcStatus
        BuildNumber = 'Version {0} (Build {1}.{2})' -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR
        InstallationLanguage = (($(locale) | Where-Object { $_ -match "LANG=" }) -split '=')[1]
        SystemUptime = uptime -p
        OSArchitecture = dpkg --print-architecture
        KernelVersion = uname -r
    }
    HardwareInformation = [HardwareInformationUnix]@{
        BIOSVersion = dmidecode -s bios-version
        SystemSKU = (dmidecode -t system)[12] | cut -d ':' -f 2 | xargs
        SystemSerialnumber = (dmidecode -t system)[9] | cut -d ':' -f 2 | xargs
        SystemManufacturer = (dmidecode -t system)[6] | cut -d ':' -f 2 | xargs
        SystemModel = (Get-WMIObject -class Win32_ComputerSystem).Model
        FreeDiskSpace = "{0:N1} GB" -f ((Get-PSDrive | Where-Object { $_.Name -eq '/' }).Free / 1GB)
        FreePhysicalMemory = "{0:N1} GB" -f (( -split (Get-Content /proc/meminfo | Where-Object { $_ -match 'MemFree:' }))[1] / 1MB)
    }
}
