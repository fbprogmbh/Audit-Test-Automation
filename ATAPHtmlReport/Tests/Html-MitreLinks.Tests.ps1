

#Import-Module
& "$PSScriptRoot\updateATAP.ps1"


InModuleScope ATAPHtmlReport {
    Describe 'Testing Links' {
        It 'test' {

            # exapmle usage
            # $map = $Sections | 
            # Where-Object { $_.Title -eq "CIS Benchmarks" } |
            # ForEach-Object { return $_.SubSections } |
            # ForEach-Object { return $_.AuditInfos } | 
            # Merge-CisAuditsToMitreMap

            # foreach ($tactic in $map.Keys) {
            #     $url = get-MitreLink -tactic -id $tactic
            #     htmlElement 'p' @{} {
            #         htmlElement 'a' @{href = $url } { $tactic }
            #         foreach ($technique in $($map[$tactic]).Keys) {
            #             $url = get-MitreLink -technique -id $technique
            #             htmlElement 'p' @{} {
            #                 htmlElement 'a' @{href = $url } { "		$technique" }
            #             }
            #         }
            #     }
            # }
        }
    }
}


