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

using module "./ATAPHtmlReport"

$args = @{
    Path = "report.html"
    Title = "IIS 10 Benchmark Report"
    ModuleName = "IIS10Audit"
    BasedOn = "CIS Microsoft IIS 10 Benchmark v1.0.0 - 03-31-2017"
    DarkMode = $true
}


Get-ATAPHtmlReport @args -Sections @(
    @{
        Title = "1"
        AuditInfos = @(
            (New-Object -TypeName AuditInfo -Property @{
                Id      = "1.1"
                Task    = "Ensure something"
                Message = "All Good"
                Audit   = [AuditStatus]::True
            })
            (New-Object -TypeName AuditInfo -Property @{
                Id      = "1.2"
                Task    = "Ensure something"
                Message = "All Good"
                Audit   = [AuditStatus]::True
            })
            (New-Object -TypeName AuditInfo -Property @{
                Id      = "1.3"
                Task    = "Ensure something"
                Message = "All Good"
                Audit   = [AuditStatus]::True
            })
            (New-Object -TypeName AuditInfo -Property @{
                Id      = "1.4"
                Task    = "Ensure something"
                Message = "Not run"
                Audit   = [AuditStatus]::None
            })
        )
    },
    @{
        Title = "2"
        SubSections = @(
            @{
                Title = "/2.1"
                AuditInfos = @(
                    (New-Object -TypeName AuditInfo -Property @{
                        Id      = "2.1.1"
                        Task    = "Ensure something else"
                        Message = "All Good"
                        Audit   = [AuditStatus]::Warning
                    }),
                    (New-Object -TypeName AuditInfo -Property @{
                        Id      = "2.1.2"
                        Task    = "Ensure something entirely different"
                        Message = "All good"
                        Audit   = [AuditStatus]::True
                    })
                )
            },
            @{
                Title = "/2.2"
                AuditInfos = @(
                    (New-Object -TypeName AuditInfo -Property @{
                        Id      = "2.2.1"
                        Task    = "Ensure something entirely different"
                        Message = "Something went wrong"
                        Audit   = [AuditStatus]::False
                    })
                    (New-Object -TypeName AuditInfo -Property @{
                        Id      = "2.2.2"
                        Task    = "Ensure something entirely different"
                        Message = "All Good"
                        Audit   = [AuditStatus]::True
                    })
                    (New-Object -TypeName AuditInfo -Property @{
                        Id      = "2.1.2"
                        Task    = "Ensure something entirely different"
                        Message = "Not quite good"
                        Audit   = [AuditStatus]::Warning
                    })
                )
            }
        )
    }
)