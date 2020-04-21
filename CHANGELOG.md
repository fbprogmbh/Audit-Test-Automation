# Changelog

## 4.0.0 Release Candidate 1

- New CIS section in **Google Chrome**.
- New CIS section in **Microsoft IE11**.
- The **Microsoft Windows Server 2019** report was added.
- New AuditGroup files that replace the dependency on the BenchmarkBucket.

### Changed

- CIS section in **Microsoft Windows 10** was updated to a new publisher version.
- CIS section in **Microsoft Windows Server 2016** was updated to a new publisher version.

### Removed

- ATAPAuditors have become deprecated.

## 4.0.0 Alpha 6

### Added

- The **Microsoft IE 11** report was added.
- The **Microsoft SQL Server 2016** report was added.

### Changed

- `Get-AuditReport` was renamed to `Get-ATAPReport`.
- Argument completion on `Get-ATAPReport` and `Save-ATAPHtmlReport` dynamically gets all report
  names instead of hard coded values.

## 4.0.0 Alpha 5

### Changed

- Instead of storing auditing functionality (the *Test* methods of the overridden *Config* classes)
  and the required information for an audit (the properties of the overridden *Config* classes) in a
  single class (the overridden *Config* classes), these two parts have been separated. Audit
  functionality is now stored in the *ATAPAuditor_\** files in the *Auditors* folder. Audit
  information is now contained in the **BenchmarkBucket** module in a separate repository.
- Every *Test* method of the overriden *Config* classes have been converted to an *ATAPAuditor*.
- **SecureWorkstation**: Now refers to the other reports and includes its data as a subesction,
  instead of duplication.
- The **FirefoxLockPrefSettings** resource is now known as **FirefoxPreferences**.

### Removed

- All benchmarks have been removed. The benchmark data has been outsourced to a separate module
  **BenchmarkBucket**.
- **AccessControls** helper was moved inside of **ATAPAuditor_AccessControls**.
- **AuditProcessingFunctions** helper is not needed anymore.
- **Benchmarks** helper was moved to **BenchmarkBucket**.
- **DomainRole** helper was moved to **ATAPAuditor**.
- **MozillaFirefox** helper was moved to **BenchmarkBucket**.
- **Report** helper was moved to **ATAPAuditor**.
- **Value** helper was moved to **BenchmarkBucket**.
- **Value** helper is not needed anymore.

### Fixed

- **FirefoxPreferences** resource: Alway returns data.

## 4.0.0 Alpha 4

### Changed

- **Save-ATAPHtmlReport**: The default save folder was moved to the *ATAPReports* folder in the
  default user *Documents*  folder. This can be overriden by the user. The path in the user
  environment variable *ATAPReportPath* will be used instead.
- **Save-ATAPHtmlReport**: If the parent folder of the path does not exist, adding *-Force* to the
  cmdlet will create the folder for you.
- The **Windows 10** report also contains the **Windows 10 GDPR** benchmarks.

### Added

- The **Windows 10 GDPR** benchmarks were added
- The **Windows 10 GDPR** report was added
- The **Helpers\\RegistryToSeparateAudit.ps1** script that converts the registry settings of a
  benchmark to a module. This is used for publishing to the old *Audit TAP* repository.
- The **Internet Explorer 11** benchmarks were added
- A changelog was added