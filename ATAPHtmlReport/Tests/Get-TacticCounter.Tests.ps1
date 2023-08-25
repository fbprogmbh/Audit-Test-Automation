#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {

    Describe "Testing Get-TacticCounter" {
        Context "When counting for a tactic without mapped tests" {
            It "Should return 0" {
                $AuditInfos = @{Id = "1.1.4"
                Status         = [AuditInfoStatus]::False
                	},
                @{Id       = "1.2.3"
                    Status = [AuditInfoStatus]::True
                },
                @{Id       = "1.2.4"
                Status = [AuditInfoStatus]::True
                },
                @{Id       = "1.2.6"
                Status = [AuditInfoStatus]::True
                },
                @{Id       = "1.2.5"
                    Status = [AuditInfoStatus]::False
                }, 
                @{Id       = "1.4.5"
                    Status = [AuditInfoStatus]::True
                }

                $Subsection = @{AuditInfos = $AuditInfos }

                $Section1 = @{Title = "Cis Benchmarks"
                    SubSections     = $Subsection
                }

                $Sections = $Section1


                $Mappings = $Sections | Where-Object { $_.Title -eq "CIS Benchmarks" } | ForEach-Object { return $_.SubSections } | ForEach-Object { return $_.AuditInfos } | Merge-CisAuditsToMitreMap
                
                $result = Get-TacticCounter -tactic $Mappings.Map["TA0042"] $Mappings.Map
                $result | Should -Be 0
            }
        }

        Context "Counter should be 1 if a technique is a 100% fullfilled" {
            It "Should be 1" {
                $AuditInfos = @{Id = "18.9.48.13"
                    Status = [AuditInfoStatus]::True
                },
                @{Id       = "18.9.87.1"
                    Status = [AuditInfoStatus]::True
                }

                $Subsection = @{AuditInfos = $AuditInfos }

                $Section1 = @{Title = "Cis Benchmarks"
                    SubSections     = $Subsection
                }

                $Sections = $Section1


                $Mappings = $Sections | Where-Object { $_.Title -eq "CIS Benchmarks" } | ForEach-Object { return $_.SubSections } | ForEach-Object { return $_.AuditInfos } | Merge-CisAuditsToMitreMap
                
                $Mappings.Map["TA0043"]["T1592"]["18.9.87.1"] | Should -Be True
                $Mappings.Map["TA0043"]["T1592"]["18.9.48.13"] | Should -Be True
                $Mappings.Map["TA0043"]["T1592"].count | Should -Be 2
                Get-TacticCounter "TA0043" $Mappings.Map | Should -Be 1
            }
        }
    }
}