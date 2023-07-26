#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'testing functions of the class MitreMap' {
        It 'tests with an example report' {
            #Dummy-Data
            $AuditInfos = 
            @{
                #Mitigation M1017
                Id = "18.9.11.1"
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1018 M1027
                Id = "1.1.4"
                Status = [AuditInfoStatus]::False
            },
            @{
                #Mitigation M1021 M1022
                Id = "5.14"
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1027
                Id = "18.2"
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1028
                Id = "18.5.11"
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1017
                Id = ""
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1017
                Id = ""
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1017
                Id = ""
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1017
                Id = ""
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1017
                Id = ""
                Status = [AuditInfoStatus]::True
            },
            @{
                #Mitigation M1027
                Id = "1.2.3"
                Status = [AuditInfoStatus]::True
            }
            $Subsection = @{AuditInfos = $AuditInfos }
            $Section1 = @{Title = "Cis Benchmarks"
                SubSections = $Subsection
            }
            
            $mitreMap = $Section1 | Where-Object { $_.Title -eq "CIS Benchmarks" } | ForEach-Object { return $_.SubSections } | ForEach-Object { return $_.AuditInfos } | Merge-CisAuditsToMitreMap
            $mitreMap.Print()

            #Tests
            $CISAMitigations = $mitreMap.Map | Get-MitigationsFromFailedTests
            $CISAMitigations.Keys | Should -Be @('M1018', 'M1027')

        } 
    }
}