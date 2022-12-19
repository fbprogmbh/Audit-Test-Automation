
[Report] @{
	Title = "Windows Server 2012 Audit Report"
	ModuleName = "ATAPAuditor"
	BasedOn = @(
		"CIS Microsoft Windows Server 2012 R2 Benchmark, Version: 2.5.0, Date: 2021-09-09",
		"DISA Microsoft Windows Server 2012 R2 Benchmark, Version: 2.19, Date: 2020-07-17"
	)
	Sections = @(
		[ReportSection] @{
			Title = "CIS Benchmarks"
			Description = "This section contains all benchmarks from CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.2.0 - 14-05-2020. WARNING: Tests in this version haven't been fully tested yet."
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2012 R2-CIS-2.5.0#RegistrySettings"
				}
				[ReportSection] @{
					Title = "User Rights Assignment"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2012 R2-CIS-2.5.0#UserRights"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2012 R2-CIS-2.5.0#AccountPolicies"
				}
				[ReportSection] @{
					Title = " Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2012 R2-CIS-2.5.0#AuditPolicies"
				}
			)
		}

		[ReportSection] @{
			Title = "DISA Benchmarks"
			Description = "This section contains all benchmarks from DISA Microsoft Windows Server 2012 R2 Benchmark v2.19"
			SubSections = @(
				[ReportSection] @{
					Title = "Registry Settings/Group Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2012 R2-DISA-2.19#RegistrySettings"
				}
				[ReportSection] @{
					Title = "Account Policies"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2012 R2-DISA-2.19#AccountPolicies"
				}
				[ReportSection] @{
					Title = " Advanced Audit Policy Configuration"
					AuditInfos = Test-AuditGroup "Microsoft Windows Server 2012 R2-DISA-2.19#AuditPolicies"
				}
			)
		}
	)
}
