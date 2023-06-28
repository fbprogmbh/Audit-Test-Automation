
#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'Testing Merge-CisAuditsToMitreMap' {
        It 'tests with an example Report' {

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

            $Section2 = @{Title = "DISA"
                $Subsection     = $null
            }

            $Sections = $Section1, $Section2


            $Mappings = $Sections | Where-Object { $_.Title -eq "CIS Benchmarks" } | ForEach-Object { return $_.SubSections } | ForEach-Object { return $_.AuditInfos } | Merge-CisAuditsToMitreMap
            
            $html = ConvertTo-HtmlTable $Mappings.map
            Write-Host $html

            $html | Should -Be "<table ><thead ><tr ><td >TA0004</td><td >TA0005</td><td >TA0001</td><td >TA0003</td><td >TA0006</td></tr></thead><tbody ><tr ><td ><p ><div >T1078 : 1 /1</div></p></td><td ><p ><div >T1078 : 1 /1</div></p></td><td ><p ><div >T1078 : 1 /1</div></p></td><td ><p ><div >T1078 : 1 /1</div></p></td><td ><p ><div >T1110 : 1 /2</div></p></td></tr></tbody></table>"
        }
    }
}