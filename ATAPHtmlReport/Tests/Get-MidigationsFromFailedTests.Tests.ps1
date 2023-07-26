#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'testing functions of the class MitreMap' {
        It 'tests with an example report' {
            #Dummy-Data
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
            #$mitreMap.Print()

            #Tests
            $mitreMap.GetType() | Should -Be "MitreMap"
            $mitreMap.Map["TA0001"]["T1078"]["1.1.4"].GetType() | Should -Be 'AuditInfoStatus'
            $mitreMap.Map["TA0001"]["T1078"]["1.1.4"] | Should -Be False
            $mitreMap.Map["TA0006"]["T1110"]["1.2.3"] | Should -Be True
            $mitreMap.Map | Get-MitigationsFromFailedTests
        } 
    }
}