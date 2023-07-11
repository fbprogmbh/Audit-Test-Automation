
#Import-Module
& "$PSScriptRoot\updateATAP.ps1"


InModuleScope ATAPHtmlReport {
    Describe 'Testing Compare-EqualCISVersions' {
        It 'Test for unmatching versions of CIS and MITRE mapping' {
            $BasedOn = @(
                "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
                "MITRE ATT&CK Mapping (based on CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark (Version: 1.11.0)), Version x.x, Date: xxxx-xx-xx"
                "DISA Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
                "Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2020-04-27"
                "ACSC Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2021, Date 2021-10-01"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            Compare-EqualCISVersions -Title "Windows 10" -BasedOn:$BasedOn | Should -Be "The CIS Version used for the MITRE mapping doesn't match with the CIS Version used for the tests."
        }
        
        It 'Test for matching versions of CIS and MITRE mapping' {
            $BasedOn = @(
                "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
                "MITRE ATT&CK Mapping (based on CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark (Version: 1.12.0)), Version x.x, Date: xxxx-xx-xx"
                "DISA Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
                "Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2020-04-27"
                "ACSC Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2021, Date 2021-10-01"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            Compare-EqualCISVersions -Title "Windows 10" -BasedOn:$BasedOn | Should -Be "The CIS Versions used for the MITRE mapping and testing are the same."
        }

        It 'Test for matching versions of CIS and MITRE mapping but wrong OS' {
            $BasedOn = @(
                "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
                "MITRE ATT&CK Mapping (based on CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark (Version: 1.12.0)), Version x.x, Date: xxxx-xx-xx"
                "DISA Windows 10 Security Technical Implementation Guide, Version: V1R16, Date: 2019-10-25"
                "Microsoft Security baseline (FINAL) for Windows 10, Version: 21H1, Date: 2021-05-18"
                "Configuration Recommendations for Hardening of Windows 10 Using Built-in Functionalities: Version 1.3, Date: 2021-05-03"
                "SiSyPHuS Recommendations for Telemetry Components: Version 1.2, Date: 2020-04-27"
                "ACSC Hardening Microsoft Windows 10 version 21H1 Workstations, Version: 10.2021, Date 2021-10-01"
                "FB Pro recommendations 'Ciphers Protocols and Hashes Benchmark', Version 1.1.0, Date: 2021-04-15"
                "FB Pro recommendations 'Enhanced settings', Version 1.1.0, Date: 2023-02-24"
            )
            Compare-EqualCISVersions -Title "Debian 10" -BasedOn:$BasedOn | Should -Be $null
        }

        It 'Test for wrong parameters' {
            # provide BasedOn with only one value in the arrey.
            $BasedOn = @(
                "CIS Microsoft Windows 10 Enterprise Release 21H1 Benchmark, Version: 1.12.0, Date: 2022-02-15"
            )
            # assert that calling this method with invalid values will throw an exception
            try {
                Compare-EqualCISVersions -Title "Windows 10" -BasedOn:$BasedOn | Should -Throw    
            }
            # empty catch block required by compiler
            catch {
                
            }
        }
    }
}