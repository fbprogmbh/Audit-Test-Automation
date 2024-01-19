#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'testing tactic order in MitreMap' {
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
            $mitreMap.Print()

            $tactics = (Get-Content -Raw "$PSScriptRoot\..\resources\MitreTactics.json" | ConvertFrom-Json).psobject.properties.name

            #check order
            $i = 0
            foreach ($tactic in $mitreMap.Map.Keys) {
                $tactic | Should -Be $tactics[$i]
                $i++
            }
        }
    }
}