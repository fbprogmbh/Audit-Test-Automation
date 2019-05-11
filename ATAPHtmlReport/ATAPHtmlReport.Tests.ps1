<#
BSD 3-Clause License

Copyright (c) 2018, FB Pro GmbH
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

Import-Module "./ATAPHtmlReport" -Force

Describe "ATAPHtmlReport" {
    InModuleScope ATAPHtmlReport {
        $testPath = "$PSScriptRoot\testreport.html"
        $args = @{
            Path = $testPath
            Title = "My Benchmark Report"
            ModuleName = "MyAudit"
            BasedOn = "My Benchmark v1.0.0 - 10-05-2017"
            # DarkMode = $true
            ComplianceStatus = $true
        }
        Get-ATAPHtmlReport @args -Sections @(
            @{
                Title = "Section 1"
                AuditInfos = @(
                    (New-ATAPAuditInfo -Id "1.1" -Task "Ensure something" -Message "All Good" -Audit True)
                    (New-ATAPAuditInfo -Id "1.2" -Task "Ensure something" -Message "All Good" -Audit True)
                    (New-ATAPAuditInfo -Id "1.3" -Task "Ensure something" -Message "All Good" -Audit True)
                    (New-ATAPAuditInfo -Id "1.4" -Task "Ensure something" -Message "Not run" -Audit None)
                )
            },
            @{
                Title = "Section 2"
                SubSections = @(
                    @{
                        Title = " Section 2.1"
                        AuditInfos = @(
                            (New-ATAPAuditInfo -Id "2.1.1" -Task "Ensure something else" -Message "All Good" -Audit Warning)
                            (New-ATAPAuditInfo -Id "2.1.2" -Task "Ensure something entirely different" -Message "All good" -Audit True)
                        )
                    },
                    @{
                        Title = "Section 2.2"
                        AuditInfos = @(
                            (New-ATAPAuditInfo -Id "2.2.1" -Task "Ensure something entirely different" -Message "Something went wrong" -Audit False)
                            (New-ATAPAuditInfo -Id "2.2.2" -Task "Text overflow can only happen on block or inline-block level elements, because the element needs to have a width in order to be overflow-ed. The overflow happens in the direction as determined by the direction property or related attributes." -Message "All Good" -Audit True)
                            (New-ATAPAuditInfo -Id "2.1.2" -Task "Ensure something entirely different" -Message "Not quite good" -Audit Warning)
                        )
                    }
                )
            }
        )

        It "New-ATAPAuditInfo" {
            $info = New-ATAPAuditInfo -Id "1" -Task "Hello" -Message "Ok" -Audit "True"
            $members = $info | Get-Member
            $specificMembers = $members | Where-Object {
                $_.MemberType -eq "Property" -and $_.Name -in "Id", "Task", "Message", "Audit"
            } 
            $specificMembers.Count | Should Be 4
        }
    
        It "Get-ATAPHtmlReport" {
            Test-Path $testPath | Should Be $true
        }
    }
}

