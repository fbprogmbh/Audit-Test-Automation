#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'Testing Get-MitreTechniqueName' {
        It 'tests with example values' {
            Get-MitreTechniqueName -TechniqueID "T1591" | Should -Be 'Gather Victim Org Information'
            Get-MitreTechniqueName -TechniqueID "T1056" | Should -Be 'Input Capture'
            Get-MitreTechniqueName -TechniqueID "T1056" | Should -BeOfType String
        }

        It 'tests with wrong values' {
            Get-MitreTechniqueName -TechniqueID "TXXXX" | Should -Be $null
            Get-MitreTechniqueName -TechniqueID "TXXXX" | Should -Not -Be 'Input Capture'
        }
    }
}