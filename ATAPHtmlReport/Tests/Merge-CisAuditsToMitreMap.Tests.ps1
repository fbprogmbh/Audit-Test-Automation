BeforeAll {
    #Import-Module
    & "$PSScriptRoot\updateATAP.ps1"
}

InModuleScope ATAPHtmlReport {
    Describe 'Testing Merge-CisAuditsToMitreMap' {
        It 'tests with an example Report' {

            $AuditInfos = @{Id = "1.1.4"
                Status         = $false
            },
            @{Id       = "1.2.3"
                Status = $true
            },
            @{Id       = "1.2.5"
                Status = $false
            }, 
            @{Id       = "1.4.5"
                Status = $true
            }

            $Subsection = @{AuditInfos = $AuditInfos }

            $Section1 = @{Title = "Cis Benchmarks"
                SubSections     = $Subsection
            }

            $Section2 = @{Title = "DISA"
                $Subsection     = $null
            }

            $Sections = $Section1, $Section2


            $mapping = $Sections | Where-Object { $_.Title -eq "CIS Benchmarks" } | ForEach-Object { return $_.SubSections } | ForEach-Object { return $_.AuditInfos } | Merge-CisAuditsToMitreMap
            foreach ($tactic in $mapping.Keys) {
                Write-Host "$tactic = "
                foreach ($technique in $($mapping[$tactic]).Keys) {
                    Write-Host "    $technique = "
                    foreach ($id in $($($mapping[$tactic])[$technique]).Keys) {
                        Write-Host "        $id = $($($($mapping[$tactic])[$technique])[$id])"
                    }
                }
            }

            $mapping["TA0001"]["T1078"]["1.1.4"] | Should -Be $false
            $mapping["TA0006"]["T1110"]["1.2.3"] | Should -Be $true
        }
    }
}