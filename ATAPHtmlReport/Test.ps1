using module ../ATAPHtmlReport

Get-ATAPHtmlReport -Path test.html -Title "IIS 10 Benchmark Report" -ModuleName "IIS10Audit" -BasedOn "CIS Microsoft IIS 10 Benchmark v1.0.0 - 03-31-2017" -Sections @(
    @{
        Title = "1"
        AuditInfos = @(
            (New-Object -TypeName AuditInfo -Property @{
                Id      = "1.1"
                Task    = "Ensure something"
                Message = "All Good"
                Audit   = [AuditStatus]::True
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
                )
            }
        )
    }
)