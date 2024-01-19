
#Import-Module
& "$PSScriptRoot\updateATAP.ps1"


InModuleScope ATAPHtmlReport {
    Describe 'Testing get-MitreLink' {
        It 'tests for tactics' {
            get-MitreLink -type tactics -id 'TA0001' | Should -Be 'https://attack.mitre.org/tactics/TA0001/'
            get-MitreLink -type tactics -id 'TA0008' | Should -Be 'https://attack.mitre.org/tactics/TA0008/'
        }
        It 'tests for techniques' {
            get-MitreLink -type techniques -id 'T1548' | Should -Be 'https://attack.mitre.org/techniques/T1548/'
            get-MitreLink -type techniques -id 'T1119' | Should -Be 'https://attack.mitre.org/techniques/T1119/'
        }
        It 'tests for techniques' {
            get-MitreLink -type mitigations -id 'M1047' | Should -Be 'https://attack.mitre.org/mitigations/M1047/'
        }
    }
}