
#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'Testing ConvertTo-HtmlTable' {
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
            
            # call the function under test and split by opening and closing brackets. Result should be an array of tags.
            $tags = (ConvertTo-HtmlTable $Mappings.map).Split("<").Split(">")
            $tags | Should -Contain 'table id="MITRETable"'
            $tags | Should -Contain 'a href="https://attack.mitre.org/tactics/TA0007/"'
            $tags | Should -Contain 'TA0007'
        }
    }
}