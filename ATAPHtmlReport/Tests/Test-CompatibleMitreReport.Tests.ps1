#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe 'Testing Check-CompatibleMitreReport' {
        It 'Testing with diffrent Reports' {
            $Title = "Windows 10 Report"
            $os = [System.Environment]::OSVersion.Platform
            Test-CompatibleMitreReport -Title $Title -os $os | Should -Be $true
            
            $Title = "Windows 11 Report"
            Test-CompatibleMitreReport -Title $Title -os $os | Should -Be $true
      
            $Title = "Windows Server 2019 Audit Report"
            Test-CompatibleMitreReport -Title $Title -os $os | Should -Be $true
       
            $Title = "Windows Server 2022 Audit Report"
            Test-CompatibleMitreReport -Title $Title -os $os | Should -Be $true
        
            $Title = "Windows 7 Report"
            Test-CompatibleMitreReport -Title $Title -os $os | Should -Be $false
        }
    }
}