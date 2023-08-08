#Import-Module
& "$PSScriptRoot\updateATAP.ps1"

InModuleScope ATAPHtmlReport {
    Describe "Testing Get-ColorValue" {
            It "Should return hundred" {
                $result = Get-ColorValue -FirstValue 10 -SecondValue 10
                $result | Should -Be "#33cca6"
            }
            It "Should return ninety" {
                $result = Get-ColorValue -FirstValue 9 -SecondValue 10
                $result | Should -Be "#52CC8F"
            }
            It "Should return eighty" {
                $result = Get-ColorValue -FirstValue 8 -SecondValue 10
                $result | Should -Be "#70CC78"
            }
            It "Should return seventy" {
                $result = Get-ColorValue -FirstValue 7 -SecondValue 10
                $result | Should -Be "#8FCC61"
            }
            It "Should return sixty" {
                $result = Get-ColorValue -FirstValue 6 -SecondValue 10
                $result | Should -Be "#ADCC4A"
            }
            It "Should return fifty" {
                $result = Get-ColorValue -FirstValue 5 -SecondValue 10
                $result | Should -Be "#CCCC33"
            }
            It "Should return fourty" {
                $result = Get-ColorValue -FirstValue 4 -SecondValue 10
                $result | Should -Be "#CCA329"
            }
            It "Should return thirty" {
                $result = Get-ColorValue -FirstValue 3 -SecondValue 10
                $result | Should -Be "#CC7A1F"
            }
            It "Should return twenty" {
                $result = Get-ColorValue -FirstValue 2 -SecondValue 10
                $result | Should -Be "#CC5214"
            }
            It "Should return ten" {
                $result = Get-ColorValue -FirstValue 1 -SecondValue 10
                $result | Should -Be "#CC290A"
            }
            It "Should return zero" {
                $result = Get-ColorValue -FirstValue 0 -SecondValue 10
                $result | Should -Be "#cc0000"
            }
            It "Should return empty" {
                $result = Get-ColorValue -FirstValue 0 -SecondValue 0
                $result | Should -Be "#a7a7a7"
            }
    }
}
