
#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'Testing MitreMap' {
        It 'tests correct amount of techniques per tacitc' {
            $mitreMap = [MitreMap]::new()
            $mitreMap.Print()

            $mitreMap.map['TA0043'].count | Should -Be 10
            $mitreMap.map['TA0042'].count | Should -Be 8
            $mitreMap.map['TA0001'].count | Should -Be 9
            $mitreMap.map['TA0002'].count | Should -Be 14
            $mitreMap.map['TA0003'].count | Should -Be 19
            $mitreMap.map['TA0004'].count | Should -Be 13
            $mitreMap.map['TA0005'].count | Should -Be 42
            $mitreMap.map['TA0006'].count | Should -Be 17
            $mitreMap.map['TA0007'].count | Should -Be 31
            $mitreMap.map['TA0008'].count | Should -Be 9
            $mitreMap.map['TA0009'].count | Should -Be 17
            $mitreMap.map['TA0011'].count | Should -Be 16
            $mitreMap.map['TA0010'].count | Should -Be 9
            $mitreMap.map['TA0040'].count | Should -Be 13
        }

        It 'tests some values' {
            $mitreMap = [MitreMap]::new()

            $mitreMap.map['TA0043'].ContainsKey('T1597') | Should -Be $true
            $mitreMap.map['TA0001'].ContainsKey('T1200') | Should -Be $true
            $mitreMap.map['TA0043'].ContainsKey('T1037') | Should -Be $false
            $mitreMap.map['TA0006'].ContainsKey('T1612') | Should -Be $false
        }
    }
}

InModuleScope ATAPHtmlReport {
    Describe 'testing read from json' {
        It 'tests if json file is read in correctly' {
            $AuditInfos = 
            @{
                Id = "1.1.4"
                Status = [AuditInfoStatus]::False
            },
            @{
                Id = "1.2.3"
                Status = [AuditInfoStatus]::True
            },
            @{
                Id = "1.2.5"
                Status = [AuditInfoStatus]::False
            }, 
            @{
                Id = "1.4.5"
                Status = [AuditInfoStatus]::True
            }
            $Subsection = @{AuditInfos = $AuditInfos }
            $Section1 = @{Title = "Cis Benchmarks"
                SubSections = $Subsection
            }
            
            $mitreMap = $Section1 | Where-Object { $_.Title -eq "CIS Benchmarks" } | ForEach-Object { return $_.SubSections } | ForEach-Object { return $_.AuditInfos } | Merge-CisAuditsToMitreMap
            $mitreMap.Print()

            #Tests
            $mitreMap.GetType() | Should -Be "MitreMap"
            $mitreMap.Map["TA0001"]["T1078"]["1.1.4"].GetType() | Should -Be 'AuditInfoStatus'
            $mitreMap.Map["TA0001"]["T1078"]["1.1.4"] | Should -Be False
            $mitreMap.Map["TA0006"]["T1110"]["1.2.3"] | Should -Be True
        }
    }
}