[Report] @{
    Title      = 'Microsoft Office Audit Report'
    ModuleName = 'ATAPAuditor'
    BasedOn    = @(
        "CIS Microsoft Office Enterprise Benchmark, Version: 1.2.0, Date: 2024-07-19"
        "Security Baseline for Microsoft 365 Apps for Enterprise, Version: 2412, Date: 2025-12-15"
        )
    Sections   = @(
        [ReportSection] @{
            Title       = "CIS Benchmarks"
            Description = "This section contains all CIS recommendations"
            SubSections = @(
                [ReportSection] @{
                    Title      = 'Registry Settings/Group Policies'
                    AuditInfos = Test-AuditGroup "Microsoft Office Enterprise-CIS-1.2.0#RegistrySettings"
                }
            )
        }
        [ReportSection] @{
            Title       = "Microsoft Benchmarks"
            Description = "This section contains all Microsoft recommendations"
            SubSections = @(
                [ReportSection] @{
                    Title      = 'Registry Settings/Group Policies'
                    AuditInfos = Test-AuditGroup "Microsoft 365 Apps for Enterprise-Microsoft-2412#RegistrySettings"
                }
            )
        }
    )
}
