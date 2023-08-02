
#Import-Module
& "$PSScriptRoot\updateATAP.ps1"


InModuleScope ATAPHtmlReport {
    Describe 'Testing Compare-EqualCISVersions' {

        It 'Test Windows 7' {
            # provide BasedOn with only one value in the arrey.
            $BasedOn = @(
                "CIS Microsoft Windows 7 Workstation Benchmark, Version: 3.1.0, Date: 2018-03-02"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            # assert that calling this method with invalid values will throw an exception
            try {
                Compare-EqualCISVersions -Title "Windows Server 2019 Audit Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $false   
            }
            # empty catch block required by compiler
            catch {
                $false | Should -Be $true
            }
        }
        It 'Test Windows 10' {
            # provide BasedOn with only one value in the arrey.
            $BasedOn = @(
                "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
                "DISA Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
                "Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2020-04-27"
                "ACSC Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2021, Date 2021-10-01"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            # assert that calling this method with invalid values will throw an exception
            try {
                Compare-EqualCISVersions -Title "Windows Server 2019 Audit Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $true    
            }
            # empty catch block required by compiler
            catch {
                $false | Should -Be $true
            }
        }
        It 'Test Windows 10 stand-alone' {
            # provide BasedOn with only one value in the arrey.
            $BasedOn = @(
                "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15"
                "BSI SiM-08202 Client unter Windows 10, Version: 1, Date: 2017-09-13"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.1, Date: 2019-07-31"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            # assert that calling this method with invalid values will throw an exception
            try {
                Compare-EqualCISVersions -Title "Windows Server 2019 Audit Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $true    
            }
            # empty catch block required by compiler
            catch {
                $false | Should -Be $true
            }
        }
        It 'Test Windows 11' {
            # provide BasedOn with only one value in the arrey.
            $BasedOn = @(
                "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14"
                "Security baseline for Microsoft Windows 11, Version: 20H2, Date: 2020-12-17"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.1, Date: 2019-07-31"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            # assert that calling this method with invalid values will throw an exception
            try {
                Compare-EqualCISVersions -Title "Windows Server 2019 Audit Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $true    
            }
            # empty catch block required by compiler
            catch {
                $false | Should -Be $true
            }
        }
        It 'Test Windows 11 stand-alone' {
            # provide BasedOn with only one value in the arrey.
            $BasedOn = @(
                "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15"
                "BSI SiM-08202 Client unter Windows 10, Version: 1, Date: 2017-09-13"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.1, Date: 2019-07-31"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            # assert that calling this method with invalid values will throw an exception
            try {
                Compare-EqualCISVersions -Title "Windows Server 2019 Audit Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $true    
            }
            # empty catch block required by compiler
            catch {
                $false | Should -Be $true
            }
        }
        It 'Test Windows Server 2019' {
            # provide BasedOn with only one value in the arrey.
            $BasedOn = @(
                "Windows Server 2019 Security Technical Implementation Guide, Version: 1.5, Date: 2020-06-17"
                "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18"
                "Microsoft Security baseline for Windows Server 2019, Version: FINAL, Date 2019-06-18"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            # assert that calling this method with invalid values will throw an exception
            try {
                Compare-EqualCISVersions -Title "Windows Server 2019 Audit Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $true    
            }
            # empty catch block required by compiler
            catch {
                $false | Should -Be $true
            }
        }
        It 'Test Windows Server 2022' {
            # provide BasedOn with only one value in the arrey.
            $BasedOn = @(
                "Security baseline for Microsoft Windows Server 2022, Version: FINAL, Date 2021-09-27"
                "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14"
                "DISA Windows Server 2022, Version: V1R1, Date 2022-09-28"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08"
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15"
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14"
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18"
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            # assert that calling this method with invalid values will throw an exception
            try {
                Compare-EqualCISVersions -Title "Windows Server 2022 Audit Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $true   
            }
            # empty catch block required by compiler
            catch {
                $false | Should -Be $true
            }
        }
        It 'Test for unmatching versions of CIS and MITRE mapping' {
            $BasedOn = @(
                "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.15.0, Date: 2023-02-15"
                "DISA Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
                "Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2020-04-27"
                "ACSC Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2021, Date 2021-10-01"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            Compare-EqualCISVersions -Title "Windows 10 Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $false
        }
        
        It 'Test for matching versions of CIS and MITRE mapping' {
            $BasedOn = @(
                "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
                "DISA Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
                "Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2020-04-27"
                "ACSC Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2021, Date 2021-10-01"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            Compare-EqualCISVersions -Title "Windows 10 Report" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $true
        }

        It 'Test for matching versions of CIS and MITRE mapping but wrong OS' {
            $BasedOn = @(
                "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
                "DISA Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
                "Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2020-04-27"
                "ACSC Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2021, Date 2021-10-01"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            $MitreMappingCompatible =   @("CIS Microsoft Windows 10 Stand-alone Benchmark, Version: 1.0.1, Date: 2022-02-08",
            "CIS Microsoft Windows 11 Stand-alone Benchmark, Version: 1.0.0, Date: 2022-11-15",
            "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15",
            "CIS Microsoft Windows 11 Enterprise Release 21H2 Benchmark, Version: 21H2, Date: 2022-02-14",
            "CIS Microsoft Windows Server 2019 Benchmark, Version: 1.3.0, Date: 2022-03-18",
            "CIS Microsoft Windows Server 2022, Version: 1.0.0, Date 2022-02-14")
            Compare-EqualCISVersions -Title "Debian 10" -ReportBasedOn:$BasedOn -MitreMappingCompatible:$MitreMappingCompatible | Should -Be $false
        }
    }
}