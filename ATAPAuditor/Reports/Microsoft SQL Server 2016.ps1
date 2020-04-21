[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
    [string]
    $SqlInstance,

    [string]
    $MachineName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $true, ParameterSetName = "ByAuditInfo")]
    [Hashtable[]]
    $InstanceAudits
)

if (get-module -ListAvailable SQLPS) {
    Import-Module SQLPS -Force
}
elseif (get-module -ListAvailable SQLServer) {
    Import-Module SQLServer -Force
}

# CIS Microsoft SQL Server 2016 Benchmark
# v1.0.0 - 08-11-2017
#
#


#
#
# CIS Microsoft SQL Server 2016 Benchmark - Audit section
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#


#
# 1 Installation, Updates and Patches
#
# This section contains recommendations related to installing and patching SQL Server.
#


#region 2 Surface Area Reduction
#
# SQL Server offers various configuration options, some of them can be controlled by the
# sp_configure stored procedure. This section contains the listing of the corresponding recommendations.

function Test-SQLAdHocDistributedQueriesDisabled {
    <#
.Synopsis
   Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'.
.DESCRIPTION
   CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

   2.1 - Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'.

   Enabling Ad Hoc Distributed Queries allows users to query data and execute statements on external data sources. This functionality should be disabled.

   This feature can be used to remotely access and exploit vulnerabilities on remote SQL Server instances and to run unsafe Visual Basic for Application functions.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.1")
    $obj | Add-Member NoteProperty Task("Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }


        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + ",`n value_in_use:" + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLClrEnabled {
    <#
.Synopsis
   Ensure 'CLR Enabled' Server Configuration Option is set to '0'.
.DESCRIPTION
   CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

   2.2 - Ensure 'CLR Enabled' Server Configuration Option is set to '0'.

   The clr enabled option specifies whether user assemblies can be run by SQL Server.

   Enabling use of CLR assemblies widens the attack surface of SQL Server and puts it at risk from both inadvertent and malicious assemblies.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.2")
    $obj | Add-Member NoteProperty Task("Ensure 'CLR Enabled' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'clr enabled';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }
        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + "`n value_in_use:" + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLCrossDBOwnershipDisabled {
    <#
.Synopsis
   Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'.
.DESCRIPTION
   CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

   2.3 - Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'

   The cross db ownership chaining option controls cross-database ownership chaining

    across all databases at the instance (or server) level.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.3")
    $obj | Add-Member NoteProperty Task("Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'cross db ownership chaining';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + "`n value_in_use:" + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLDatabaseMailXPsDisabled {
    <#
.Synopsis
   Ensure 'Database Mail XPs' Server Configuration Option is set to '0'.
.DESCRIPTION
   CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

   2.4 - Ensure 'Database Mail XPs' Server Configuration Option is set to '0'.

   The Database Mail XPs option controls the ability to generate and transmit email messages from SQL Server.

   Disabling the Database Mail XPs option reduces the SQL Server surface, eliminates a DOS attack vector and channel to exfiltrate data from the database server to a remote host.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.4")
    $obj | Add-Member NoteProperty Task("Ensure 'Database Mail XPs' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Database Mail XPs';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + "`n value_in_use:" + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }

    Write-Output $obj
}

function Test-SQLOleAutomationProceduresDisabled {
    <#
.Synopsis
   Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0'.
.DESCRIPTION
   CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

   2.5 - Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0'.

   The Ole Automation Procedures option controls whether OLE Automation objects can be instantiated within Transact-SQL batches. These are extended stored procedures that allow SQL Server users to execute functions external to SQL Server.

   Disabling the Database Mail XPs option reduces the SQL Server surface, eliminates a DOS attack vector and channel to exfiltrate data from the database server to a remote host.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.5")
    $obj | Add-Member NoteProperty Task("Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + "`n value_in_use:" + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLRemoteAccessDisabled {
    <#
.Synopsis
   Ensure 'Remote Access' Server Configuration Option is set to '0'.
.DESCRIPTION
   CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

   2.6 - Ensure 'Remote Access' Server Configuration Option is set to '0'.

   The remote access option controls the execution of local stored procedures on remote servers or remote stored procedures on local server.

   Functionality can be abused to launch a Denial-of-Service (DoS) attack on remote servers by off-loading query processing to a target.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.6")
    $obj | Add-Member NoteProperty Task("Ensure 'Remote Access' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'remote access';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + "`n value_in_use: " + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLRemoteAdminConnectionsDisabled {
    <#
.Synopsis
    Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.7 - Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'

    The remote admin connections option controls whether a client application on a remote computer can use the Dedicated Administrator Connection (DAC).

     The Dedicated Administrator Connection (DAC) lets an administrator access a running server to execute diagnostic functions or Transact-SQL statements, or to troubleshoot
    problems on the server, even when the server is locked or running in an abnormal state and not responding to a SQL Server Database Engine connection. In a cluster scenario, the
    administrator may not actually be logged on to the same node that is currently hosting the SQL Server instance and thus is considered "remote". Therefore, this setting should usually
    be enabled (1) for SQL Server failover clusters; otherwise it should be disabled (0) which is the default.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.7")
    $obj | Add-Member NoteProperty Task("Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'remote admin connections' AND SERVERPROPERTY('IsClustered') = 0;"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + "`n value_in_use:" + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLScanForStartupProcsDisabled {
    <#
.Synopsis
    Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.8 - Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'.

    The scan for startup procs option, if enabled, causes SQL Server to scan for and automatically run all stored procedures that are set to execute upon service startup.

    Enforcing this control reduces the threat of an entity leveraging these facilities for malicious purposes.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.8")
    $obj | Add-Member NoteProperty Task("Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'scan for startup procs';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + "`n value_in_use:" + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLTrustworthyDatabaseOff {
    <#
.Synopsis
    Ensure 'Trustworthy' Database Property is set to 'Off'.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.9 - Ensure 'Trustworthy' Database Property is set to 'Off'.

    The TRUSTWORTHY database option allows database objects to access objects in other databases under certain circumstances.

    Provides protection from malicious CLR assemblies or extended procedures.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.9")
    $obj | Add-Member NoteProperty Task("Ensure 'Trustworthy' Database Property is set to 'Off'")

    $query = "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Found $sqlResult.name")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLServerProtocolsDisabled {
    <#
.Synopsis
    Ensure Unnecessary SQL Server Protocols are set to 'Disabled'.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.10 - Ensure Unnecessary SQL Server Protocols are set to 'Disabled'.

    SQL Server supports Shared Memory, Named Pipes, and TCP/IP protocols. However, SQL Server should be configured to use the bare minimum required based on the organization's needs.

    Using fewer protocols minimizes the attack surface of SQL Server and, in some cases, can protect it from remote attacks.
#>
    [CmdletBinding()]
    param(
        [string] $SqlInstance = "MSSQLSERVER",

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.10")
    $obj | Add-Member NoteProperty Task("Ensure Unnecessary SQL Server Protocols are set to 'Disabled'")

    $protocols = "np", "sm", "tcp"
    $smo = 'Microsoft.SqlServer.Management.Smo.'
    $wmi = New-Object ($smo + 'Wmi.ManagedComputer')

    try {
        $singleWmi = $wmi | Where-Object {$_.Name -eq $machineName}
        $foundProtocols = @()
        foreach ($protocol in $protocols) {
            $uri = "ManagedComputer[@Name='$machineName']/ServerInstance[@Name='$sqlInstance']/ServerProtocol[@Name='$protocol']"
            $p = $singleWmi.GetsmoObject($uri)
            if ($p.isEnabled) {
                $foundProtocols += $p.displayName
            }
        }
        [string]$s = $null
        $s = $foundProtocols -join ", "

        if ($foundProtocols.Count -eq 0) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        elseif ($foundProtocols.Count -eq 1) {
            $obj | Add-Member NoteProperty Status("Only one Protocol is enabled: " + $s)
            $obj | Add-Member NoteProperty Audit("True")
        }
        elseif ($foundProtocols.Count -eq 2) {
            $obj | Add-Member NoteProperty Status("Following protocols are enabled: " + $s)
            $obj | Add-Member NoteProperty Audit("Warning")
        }
        else {
            $obj | Add-Member NoteProperty Status("Following protocols are enabled: " + $s)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Mangement.Automation.MethodInvocationException] {
        $obj | Add-Member NoteProperty Status("MachineName not found or sqlInstance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLUseNonStandardPorts {
    <#
.Synopsis
    Ensure SQL Server is configured to use non-standard ports.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.11 - Ensure SQL Server is configured to use non-standard ports.

    The TRUSTWORTHY database option allows database objects to access objects in other databases under certain circumstances.

    Provides protection from malicious CLR assemblies or extended procedures.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "By Instance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.11")
    $obj | Add-Member NoteProperty Task("Ensure SQL Server is configured to use non-standard ports")

    $query = "DECLARE @value nvarchar(256);
                EXECUTE master.dbo.xp_instance_regread
                    N'HKEY_LOCAL_MACHINE',
                    N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib\Tcp\IPAll',
                    N'TcpPort',
                    @value OUTPUT,
                    N'no_output';
                SELECT @value AS TCP_Port WHERE @value = '1433';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("TCP port 1433 in use")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLHideInstanceEnabled {
    <#
.Synopsis
    Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.12 - Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances.

    Non-clustered SQL Server instances within production environments should be designated as hidden to prevent advertisement by the SQL Server Browser service.

    Designating production SQL Server instances as hidden leads to a more secure installation because they cannot be enumerated. However, clustered instances may break if this option is selected.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.12")
    $obj | Add-Member NoteProperty Task("Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances")

    $query = "DECLARE @getValue INT;
                EXEC master..xp_instance_regread
                @rootkey = N'HKEY_LOCAL_MACHINE',
                @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
                @value_name = N'HideInstance',
                @value = @getValue OUTPUT;
                SELECT @getValue AS Hide_Instance;"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $sqlResult.Hide_Instance -eq 1 ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Instance not hidden")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLSaLoginAccountDisabled {
    <#
.Synopsis
    Ensure the 'sa' Login Account is set to 'Disabled'.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.13 - Ensure the 'sa' Login Account is set to 'Disabled'.

    The sa account is a widely known and often widely used SQL Server account with sysadmin privileges. This is the original login created during installation and always has the principal_id=1 and sid=0x01.

    Enforcing this control reduces the probability of an attacker executing brute force attacks against a well-known principal.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.13")
    $obj | Add-Member NoteProperty Task("Ensure the 'sa' Login Account is set to 'Disabled'")

    $query = "SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("SA Login Account enabled")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLSaLoginAccountRenamed {
    <#
.Synopsis
    Ensure the 'sa' Login Account has been renamed.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.14 - Ensure the 'sa' Login Account has been renamed.

    The sa account is a widely known and often widely used SQL Server account with sysadmin privileges. This is the original login created during installation and always has the principal_id=1 and sid=0x01.

    It is more difficult to launch password-guessing and brute-force attacks against the sa login if the name is not known.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.14")
    $obj | Add-Member NoteProperty Task(" Ensure the 'sa' Login Account has been renamed")

    $query = "SELECT name FROM sys.server_principals WHERE sid = 0x01"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ($sqlResult.name -ne "sa") {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("SA Login Account not renamed")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLXpCommandShellDisabled {
    <#
.Synopsis
    Ensure 'xp_cmdshell' Server Configuration Option is set to '0'.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.15 - Ensure 'xp_cmdshell' Server Configuration Option is set to '0'.

    The xp_cmdshell option controls whether the xp_cmdshell extended stored procedure can be used by an authenticated SQL Server user to execute operating-system command shell commands and return results as rows within the SQL client.

    The xp_cmdshell procedure is commonly used by attackers to read or write data to/from the underlying Operating System of a database server.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.15")
    $obj | Add-Member NoteProperty Task("Ensure 'xp_cmdshell' Server Configuration Option is set to '0'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( ($sqlResult.value_configured -eq 0) -and ($sqlResult.value_in_use -eq 0) ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Values do not match, found: `n value_configured: " + $sqlResult.value_configured + "`n value_in_use:" + $sqlResult.value_in_use)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLAutoCloseOff {
    <#
.Synopsis
    Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.16 - Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases.

    AUTO_CLOSE determines if a given database is closed or not after a connection terminates. If enabled, subsequent connections to the given database will require the database to be
    reopened and relevant procedure caches to be rebuilt.

    Because authentication of users for contained databases occurs within the database not at the server\instance level, the database must be opened every time to authenticate a user.
    The frequent opening/closing of the database consumes additional server resources and may contribute to a denial of service.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.16")
    $obj | Add-Member NoteProperty Task(" Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases")

    $query = "SELECT name, containment, containment_desc, is_auto_close_on FROM sys.databases WHERE containment <> 0 and is_auto_close_on = 1;"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult.name) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("AUTO_CLOSE not set to OFF")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLNoSaAccounnt {
    <#
.Synopsis
    Ensure no login exists with the name 'sa'.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 2 Surface Area Reduction

    2.17 - Ensure no login exists with the name 'sa'.

    The sa login (e.g. principal) is a widely known and often widely used SQL Server account.Therefore, there should not be a login called sa even when the original sa login (principal_id = 1) has been renamed.

    Enforcing this control reduces the probability of an attacker executing brute force attacks against a well-known principal name.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("2.17")
    $obj | Add-Member NoteProperty Task("Ensure no login exists with the name 'sa'")

    $query = "SELECT principal_id, name FROM sys.server_principals WHERE name = 'sa';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult.name) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Found login with name 'sa'")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}
#endregion

#region 3 Authentication and Authorization
#
# This section contains recommendations related to SQL Server's authentication and authorization mechanisms.
#

function Test-SQLServerAuthentication {
    <#
.Synopsis
    Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.1 - Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'.

    Uses Windows Authentication to validate attempted connections.

    Windows provides a more robust authentication mechanism than SQL Server authentication.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("3.1")
    $obj | Add-Member NoteProperty Task("Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'")

    $query = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') as [login_mode];"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $sqlResult.login_mode -eq 1 ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        elseif ( $sqlResult.login_mode -eq 0 ) {
            $obj | Add-Member NoteProperty Status("Login mode set to Mixed Mode Authentication")
            $obj | Add-Member NoteProperty Audit("False")
        }
        else {
            $obj | Add-Member NoteProperty Status("An unknown error occured")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLGuestPermissionOnDatabases {
    <#
.Synopsis
    Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases excluding the master, msdb and tempdb.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.2 - Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases excluding the master, msdb and tempdb.

    Remove the right of the guest user to connect to SQL Server databases, except for master, msdb, and tempdb.

    A login assumes the identity of the guest user when a login has access to SQL Server but does not have access to a database through its own account and the database has a guest
    user account. Revoking the CONNECT permission for the guest user will ensure that a login is not able to access database information without explicit access to do so.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $databases = Get-SqlDatabase -ServerInstance $instanceName -ErrorAction Stop | Select-Object -ExpandProperty name
        }
        else {
            $databases = Get-SqlDatabase -ServerInstance $MachineName -ErrorAction Stop | Select-Object -ExpandProperty name
        }

        $databases = {$databases}.Invoke()
        if ($databases.Remove("master")) {
        }
        if ($databases.Remove("msdb")) {
        }
        if ($databases.Remove("tempdb")) {
        }
        $index = 1

        foreach ($database in $databases) {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty ID("3.2.$index")
            $obj | Add-Member NoteProperty Task("Ensure CONNECT permissions on the 'guest' user is revoked for database $database")
            $query = "USE [$database]; " + `
                "SELECT DB_NAME() AS DatabaseName, 'guest' AS Database_User, [permission_name], [state_desc]
                        FROM sys.database_permissions
                        WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest')
                        AND [state_desc] LIKE 'GRANT%'
                        AND [permission_name] = 'CONNECT'
                        AND DB_NAME() NOT IN ('master','tempdb','msdb');"

            try {
                if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
                }
                else {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
                }

                if ( $null -eq $sqlResult ) {
                    $obj | Add-Member NoteProperty Status("All good")
                    $obj | Add-Member NoteProperty Audit("True")
                }
                else {
                    $obj | Add-Member NoteProperty Status("Got $sqlResult")
                    $obj | Add-Member NoteProperty Audit("False")
                }
            }
            catch [System.Data.SqlClient.SqlException] {
                $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
                $obj | Add-Member NoteProperty Audit("Warning")
            }
            Write-Output $obj

            $index++
        }
    }
    catch {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty ID("3.2")
        $obj | Add-Member NoteProperty Task("Ensure CONNECT permissions on the 'guest' user is revoked for database $database")
        $obj | Add-Member NoteProperty Status("Failed to connect to server $instanceName")
        $obj | Add-Member NoteProperty Audit("Warning")
        Write-Output $obj
    }
}

function Test-SQLDropOrphanedUsers {
    <#
.Synopsis
    Ensure 'Orphaned Users' are Dropped From SQL Server Databases.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.3 - Ensure 'Orphaned Users' are Dropped From SQL Server Databases.

    A database user for which the corresponding SQL Server login is undefined or is incorrectly defined on a server instance cannot log in to the instance and is referred to as orphaned and should be removed.

    Orphan users should be removed to avoid potential misuse of those broken users in any way.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $databases = Get-SqlDatabase -ServerInstance $instanceName -ErrorAction Stop | Select-Object -ExpandProperty name
        }
        else {
            $databases = Get-SqlDatabase -ServerInstance $MachineName -ErrorAction Stop | Select-Object -ExpandProperty name
        }

        $index = 1

        foreach ($database in $databases) {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty ID("3.3.$index")
            $obj | Add-Member NoteProperty Task("Ensure 'Orphaned Users' are dropped for database $database")

            $query = "USE [$database];
                        GO
                        EXEC sp_change_users_login @Action='Report';"

            try {
                if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
                }
                else {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
                }

                if ( $null -eq $sqlResult ) {
                    $obj | Add-Member NoteProperty Status("All good")
                    $obj | Add-Member NoteProperty Audit("True")
                }
                else {
                    $obj | Add-Member NoteProperty Status("Got $sqlResult")
                    $obj | Add-Member NoteProperty Audit("False")
                }
            }
            catch [System.Data.SqlClient.SqlException] {
                $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
                $obj | Add-Member NoteProperty Audit("Warning")
            }

            Write-Output $obj

            $index++
        }
    }
    catch {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty ID("3.3")
        $obj | Add-Member NoteProperty Task("Ensure 'Orphaned Users' are dropped for database $database")
        $obj | Add-Member NoteProperty Status("Failed to connect to server $instanceName")
        $obj | Add-Member NoteProperty Audit("Warning")
        Write-Output $obj
    }
}

function Test-SQLAuthenticationDisabled {
    <#
.Synopsis
    Ensure SQL Authentication is not used in contained databases.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.4 - Ensure SQL Authentication is not used in contained databases.

    Contained databases do not enforce password complexity rules for SQL Authenticated users.

    The absence of an enforced password policy may increase the likelihood of a weak credential being established in a contained database.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $databases = Get-SqlDatabase -ServerInstance $instanceName -ErrorAction Stop | Select-Object -ExpandProperty name
        }
        else {
            $databases = Get-SqlDatabase -ServerInstance $MachineName -ErrorAction Stop | Select-Object -ExpandProperty name
        }

        if ($databases.Count -eq 0) {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty ID("7.1")
            $obj | Add-Member NoteProperty Task("Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases")
            $obj | Add-Member NoteProperty Status("No databases found")
            $obj | Add-Member NoteProperty Audit("Warning")
            Write-Output $obj
        }

        $index = 1

        foreach ($database in $databases) {

            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty ID("3.4.$index")
            $obj | Add-Member NoteProperty Task("Ensure SQL Authentication is not used for database $database")

            $query = "USE [$database];
                            GO
                            SELECT name AS DBUser
                            FROM sys.database_principals
                            WHERE name NOT IN ('dbo','Information_Schema','sys','guest')
                            AND type IN ('U','S','G')
                            AND authentication_type = 2;
                            GO"

            try {
                if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
                }
                else {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
                }

                if ( $null -eq $sqlResult ) {
                    $obj | Add-Member NoteProperty Status("All good")
                    $obj | Add-Member NoteProperty Audit("True")
                }
                else {
                    $obj | Add-Member NoteProperty Status("Got $sqlResult")
                    $obj | Add-Member NoteProperty Audit("False")
                }
            }
            catch [System.Data.SqlClient.SqlException] {
                $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
                $obj | Add-Member NoteProperty Audit("Warning")
            }

            Write-Output $obj

            $index++
        }
    }
    catch {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty ID("3.4")
        $obj | Add-Member NoteProperty Task("Ensure CONNECT permissions on the 'guest' user is revoked for database $database")
        $obj | Add-Member NoteProperty Status("Ensure SQL Authentication is not used for database $database")
        $obj | Add-Member NoteProperty Audit("Warning")
        Write-Output $obj
    }
}

function Test-SQLServerServiceAccountIsNotAnAdministrator {
    <#
.Synopsis
    Ensure the SQL Server’s MSSQL Service Account is Not an Administrator
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.5 - Ensure the SQL Server’s MSSQL Service Account is Not an Administrator

    The service account and/or service SID used by the MSSQLSERVER service for a default instance or MSSQL$<InstanceName> service for a named instance should not be a member of the Windows Administrator group either directly or indirectly (via a group). This also means that the account known as LocalSystem (aka NT AUTHORITY\SYSTEM) should not be used for the MSSQL service as this account has higher privileges than the SQL Server service requires.

    Following the principle of least privilege, the service account should have no more privileges than required to do its job. For SQL Server services, the SQL Server Setup will assign the required permissions directly to the service SID. No additional permissions or privileges should be necessary.
#>
    [CmdletBinding()]
    param(
        [string] $MachineName = $env:COMPUTERNAME
    )
    $obj = New-Object psobject
    $obj | Add-Member NoteProperty ID("3.5")
    $obj | Add-Member NoteProperty Task("Ensure the SQL Server’s MSSQL Service Account is Not an Administrator")


    $smo = 'Microsoft.SqlServer.Management.Smo.'
    $wmi = New-Object ($smo + 'Wmi.ManagedComputer')
    $singleWmi = $wmi | Where-Object {$_.Name -eq $machineName}
    $sqlServer = $singleWmi.Services | Where-Object {$_.Type -eq "SqlServer"}
    $serviceAccountNames = @()
    foreach ($sqlS in $sqlServer) {
        $serviceAccountNames += $sqlS.ServiceAccount.Substring($sqlS.serviceAccount.IndexOf("\") + 1 )
    }

    $ADSIComputer = [ADSI]("WinNT://$machineName,computer")
    try {
        $group = $ADSIComputer.psbase.children.find('Administrators', 'Group')
    }
    catch {
        try {
            $group = $ADSIComputer.psbase.children.find('Administratoren', 'Group')
        }
        catch [System.Mangement.Automation.MethodInvocationException] {
            $obj | Add-Member NoteProperty Status("MachineName not found")
            $obj | Add-Member NoteProperty Audit("Warning")
            return Write-Output $obj
        }
    }

    $members = $group.psbase.invoke("members")  | ForEach-Object {
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
    }
    $admins = @()

    foreach ($member in $members) {
        try {
            # Try if $member is a AD group and get all members of this group including all nested groups
            $admins += (Get-ADGroupMember $member -Recursive | Select-Object -ExpandProperty SamAccountName)
        }
        catch {
            # TODO catch unterscheiden nach nicht gefunden oder active directory Fehler
            # If it is not a AD group, it has to be a local account, so add it (we assume local groups are not used inside the company)
            $admins += $member
        }
    }
    foreach ($serviceAccountName in $serviceAccountNames) {
        foreach ($admin in $admins) {
            if ($admin -eq $serviceAccountName) {
                $sqlAdmins += $serviceAccountName
            }
        }
    }
    if ($null -eq $sqlAdmins) {
        $obj | Add-Member NoteProperty Status("All good")
        $obj | Add-Member NoteProperty Audit("True")
    }
    else {
        $obj | Add-Member NoteProperty Status("Following service accounts are administrator: " + $sqlAdmins)
        $obj | Add-Member NoteProperty Audit("False")
    }
    Write-Output $obj
}

function Test-SQLAgentServiceAccountIsNotAnAdministrator {
    <#
.Synopsis
    Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.6 - Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator

    The service account and/or service SID used by the SQLSERVERAGENT service for a default instance or SQLAGENT$<InstanceName> service for a named instance should not be a member of the Windows Administrator group either directly or indirectly (via a group). This also means that the account known as LocalSystem (aka NT AUTHORITY\SYSTEM) should not be used for the SQLAGENT service as this account has higher privileges than the SQL Server service requires.

    Following the principle of least privilege, the service account should have no more privileges than required to do its job. For SQL Server services, the SQL Server Setup will assign the required permissions directly to the service SID. No additional permissions or privileges should be necessary.
#>
    [CmdletBinding()]
    param(
        [string] $MachineName = $env:COMPUTERNAME
    )
    $obj = New-Object psobject
    $obj | Add-Member NoteProperty ID("3.6")
    $obj | Add-Member NoteProperty Task("Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator")

    $smo = 'Microsoft.SqlServer.Management.Smo.'
    $wmi = New-Object ($smo + 'Wmi.ManagedComputer')
    $singleWmi = $wmi | Where-Object {$_.Name -eq $machineName}
    $sqlAgent = $singleWmi.Services | Where-Object {$_.Type -eq "SqlAgent"}
    $sqlAgentNames = @()
    foreach ($sqlS in $sqlAgent) {
        $sqlAgentNames += $sqlS.ServiceAccount.Substring($sqlS.serviceAccount.IndexOf("\") + 1 )
    }

    $ADSIComputer = [ADSI]("WinNT://$machineName,computer")

    try {
        $group = $ADSIComputer.psbase.children.find('Administrators', 'Group')
    }
    catch {
        try {
            $group = $ADSIComputer.psbase.children.find('Administratoren', 'Group')
        }
        catch [System.Mangement.Automation.MethodInvocationException] {
            $obj | Add-Member NoteProperty Status("MachineName not found")
            $obj | Add-Member NoteProperty Audit("Warning")
            return Write-Output $obj
        }
    }

    $members = $group.psbase.invoke("members")  | ForEach-Object {
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
    }
    $admins = @()

    foreach ($member in $members) {
        try {
            # Try if $member is a AD group and get all members of this group including all nested groups
            $admins += (Get-ADGroupMember $member -Recursive | Select-Object -ExpandProperty SamAccountName)
        }
        catch {
            # TODO catch unterscheiden nach nicht gefunden oder active directory Fehler
            # If it is not a AD group, it has to be a local account, so add it (we assume local groups are not used inside the company)
            $admins += $member
        }
    }
    foreach ($sqlAgentName in $sqlAgentNames) {
        foreach ($admin in $admins) {
            if ($admin -eq $sqlAgentName) {
                $sqlAdmins += $sqlAgentName
            }
        }
    }
    if ($null -eq $sqlAdmins) {
        $obj | Add-Member NoteProperty Status("All good")
        $obj | Add-Member NoteProperty Audit("True")
    }
    else {
        $obj | Add-Member NoteProperty Status("Following service accounts are administrator: " + $sqlAdmins)
        $obj | Add-Member NoteProperty Audit("False")
    }
    Write-Output $obj
}

function Test-SQLFullTextServiceAccountIsNotAnAdministrator {
    <#
.Synopsis
    Ensure the SQL Server’s Full-Text Service Account is Not an Administrator
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.7 - Ensure the SQL Server’s Full-Text Service Account is Not an Administrator

    The service account and/or service SID used by the MSSQLFDLauncher service for a default instance or MSSQLFDLauncher$<InstanceName> service for a named instance should not be a member of the Windows Administrator group either directly or indirectly (via a group). This also means that the account known as LocalSystem (aka NT AUTHORITY\SYSTEM) should not be used for the Full-Text service as this account has higher privileges than the SQL Server service requires.

    Following the principle of least privilege, the service account should have no more privileges than required to do its job. For SQL Server services, the SQL Server Setup will assign the required permissions directly to the service SID. No additional permissions or privileges should be necessary.
#>
    [CmdletBinding()]
    param(
        [string] $MachineName = $env:COMPUTERNAME
    )
    $obj = New-Object psobject
    $obj | Add-Member NoteProperty ID("3.7")
    $obj | Add-Member NoteProperty Task("Ensure the SQL Server’s Full-Text Service Account is Not an Administrator")

    $smo = 'Microsoft.SqlServer.Management.Smo.'
    $wmi = New-Object ($smo + 'Wmi.ManagedComputer')
    $singleWmi = $wmi | Where-Object {$_.Name -eq $machineName}
    $sqlServices = $singleWmi.Services | Where-Object {$_.Type -eq "9"}
    $sqlServiceNames = @()
    foreach ($sqlS in $sqlServices) {
        $sqlServiceNames += $sqlS.ServiceAccount.Substring($sqlS.serviceAccount.IndexOf("\") + 1 )
    }

    $ADSIComputer = [ADSI]("WinNT://$machineName,computer")

    try {
        $group = $ADSIComputer.psbase.children.find('Administrators', 'Group')
    }
    catch {
        try {
            $group = $ADSIComputer.psbase.children.find('Administratoren', 'Group')
        }
        catch [System.Mangement.Automation.MethodInvocationException] {
            $obj | Add-Member NoteProperty Status("MachineName not found")
            $obj | Add-Member NoteProperty Audit("Warning")
            return Write-Output $obj
        }
    }

    $members = $group.psbase.invoke("members")  | ForEach-Object {
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
    }
    $admins = @()

    foreach ($member in $members) {
        try {
            # Try if $member is a AD group and get all members of this group including all nested groups
            $admins += (Get-ADGroupMember $member -Recursive | Select-Object -ExpandProperty SamAccountName)
        }
        catch {
            # TODO catch unterscheiden nach nicht gefunden oder active directory Fehler
            # If it is not a AD group, it has to be a local account, so add it (we assume local groups are not used inside the company)
            $admins += $member
        }
    }
    foreach ($sqlServiceName in $sqlServiceNames) {
        foreach ($admin in $admins) {
            if ($admin -eq $sqlServiceName) {
                $sqlAdmins += $sqlServiceName
            }
        }
    }
    if ($null -eq $sqlAdmins) {
        $obj | Add-Member NoteProperty Status("All good")
        $obj | Add-Member NoteProperty Audit("True")
    }
    else {
        $obj | Add-Member NoteProperty Status("Following service accounts are administrator: " + $sqlAdmins)
        $obj | Add-Member NoteProperty Audit("False")
    }
    Write-Output $obj
}

function Test-SQLPermissionsForRolePublic {
    <#
.Synopsis
    Ensure only the default permissions specified by Microsoft are granted to the public server role.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.8 - Ensure only the default permissions specified by Microsoft are granted to the public server role.

    public is a special fixed server role containing all logins. Unlike other fixed server roles, permissions can be changed for the public role. In keeping with the principle of least
    privileges, the public server role should not be used to grant permissions at the server scope as these would be inherited by all users.

    Every SQL Server login belongs to the public role and cannot be removed from this role. Therefore, any permissions granted to this role will be available to all logins unless they
    have been explicitly denied to specific logins or user-defined server roles.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("3.8")
    $obj | Add-Member NoteProperty Task("Ensure only the default permissions specified by Microsoft are granted to the public server role")

    $query = "SELECT *
                FROM master.sys.server_permissions
                WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE
                'GRANT%')
                AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE'
                and class_desc = 'SERVER')
                AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
                class_desc = 'ENDPOINT' and major_id = 2)
                AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
                class_desc = 'ENDPOINT' and major_id = 3)
                AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
                class_desc = 'ENDPOINT' and major_id = 4)
                AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and
                class_desc = 'ENDPOINT' and major_id = 5);"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Found Permission:" + $sqlResult.permission_name)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLWindowsBuiltinNoSqlLogin {
    <#
.Synopsis
    Ensure Windows BUILTIN groups are not SQL Logins.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.9 - Ensure Windows BUILTIN groups are not SQL Logins.

    Prior to SQL Server 2008, the BUILTIN\Administrators group was added a SQL Server login with sysadmin privileges during installation by default. Best practices promote
    creating an Active Directory level group containing approved DBA staff accounts and using this controlled AD group as the login with sysadmin privileges. The AD group should be
    specified during SQL Server installation and the BUILTIN\Administrators group would therefore have no need to be a login.

    The BUILTIN groups (Administrators, Everyone, Authenticated Users, Guests, etc.) generally contain very broad memberships which would not meet the best practice of ensuring only
    necessary users have been granted access to a SQL Server instance. These groups should not be used for any level of access into a SQL Server Database Engine instance.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("3.9")
    $obj | Add-Member NoteProperty Task("Ensure Windows BUILTIN groups are not SQL Logins")

    $query = "SELECT pr.[name], pe.[permission_name], pe.[state_desc]
                FROM sys.server_principals pr
                JOIN sys.server_permissions pe
                ON pr.principal_id = pe.grantee_principal_id
                WHERE pr.name like 'BUILTIN%';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Found Account(s):" + $sqlResult.name)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLWindowsLocalGroupsNoSqlLogin {
    <#
.Synopsis
    Ensure Windows local groups are not SQL Logins.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.10 - Ensure Windows local groups are not SQL Logins.

    Local Windows groups should not be used as logins for SQL Server instances.

    Allowing local Windows groups as SQL Logins provides a loophole whereby anyone with OS level administrator rights (and no SQL Server rights) could add users to the local
    Windows groups and thereby give themselves or others access to the SQL Server instance.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("3.10")
    $obj | Add-Member NoteProperty Task("Ensure Windows local groups are not SQL Logins")

    $query = "USE [master]
                GO
                SELECT pr.[name] AS LocalGroupName, pe.[permission_name], pe.[state_desc]
                FROM sys.server_principals pr
                JOIN sys.server_permissions pe
                ON pr.[principal_id] = pe.[grantee_principal_id]
                WHERE pr.[type_desc] = 'WINDOWS_GROUP'
                AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Found Group(s):" + $sqlResult.LocalGroupName)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLPublicRoleMsdbDatabase {
    <#
.Synopsis
    Ensure the public role in the msdb database is not granted access to SQL Agent proxies.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 3  Authentication and Authorization

    3.11 - Ensure the public role in the msdb database is not granted access to SQL Agent proxies.

    Local Windows groups should not be used as logins for SQL Server instances.

    Allowing local Windows groups as SQL Logins provides a loophole whereby anyone with OS level administrator rights (and no SQL Server rights) could add users to the local
    Windows groups and thereby give themselves or others access to the SQL Server instance.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("3.11")
    $obj | Add-Member NoteProperty Task("Ensure the public role in the msdb database is not granted access to SQL Agent proxies")

    $query = "USE [msdb]
                GO
                SELECT sp.name AS proxyname
                FROM dbo.sysproxylogin spl
                JOIN sys.database_principals dp
                ON dp.sid = spl.sid
                JOIN sysproxies sp
                ON sp.proxy_id = spl.proxy_id
                WHERE principal_id = USER_ID('public');
                GO"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Found:" + $sqlResult.proxyname)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}
#endregion

#region 4 Password Policies
#
# This section contains recommendations related to SQL Server's password policies.
#

function Test-SQLMustChangeOptionIsOn {
    <#
.Synopsis
    Ensure the public role in the msdb database is not granted access to SQL Agent proxies.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 4  Password Policies

    4.1 - Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins.

    Whenever this option is set to ON, SQL Server will prompt for an updated password the first time the new or altered login is used.

    Enforcing a password change after a reset or new login creation will prevent the account administrators or anyone accessing the initial password from misuse of the SQL login created without being noticed.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("4.1")
    $obj | Add-Member NoteProperty Task("Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins")

    $query = "SELECT name, create_date
                FROM sys.sql_logins"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlLogins = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlLogins = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        $mustChangeLogins = @()
        foreach ($sqlLogin in $sqlLogins) {
            $loginName = $sqlLogin.name
            $query2 = "SELECT LOGINPROPERTY('$loginName', 'PasswordLastSetTime') AS 'PasswordLastSetTime'"

            if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $SqlInstance -ne "MSSQLSERVER") {
                $loginProperty = Invoke-Sqlcmd -Query $query2 -ServerInstance $instanceName -ErrorAction Stop
            }
            else {
                $loginProperty = Invoke-Sqlcmd -Query $query2 -ServerInstance $MachineName -ErrorAction Stop
            }

            if ((Get-Date $sqlLogin.create_date) -gt (Get-Date $loginProperty.PasswordLastSetTime)) {
                $mustChangeLogins += $sqlLogin
            }
        }
        if ($mustChangeLogins.Count -gt 0) {
            $obj | Add-Member NoteProperty Status("Following Logins Must Change their password: " + $mustChangeLogins.name)
            $obj | Add-Member NoteProperty Audit("False")

        }
        else {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }

    Write-Output $obj
}

function Test-SQLCheckExpirationOptionOn {
    <#
.Synopsis
    Ensure the public role in the msdb database is not granted access to SQL Agent proxies.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 4  Password Policies

    4.2 - Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role.

    Applies the same password expiration policy used in Windows to passwords used inside SQL Server.

    Ensuring SQL logins comply with the secure password policy applied by the Windows Server Benchmark will ensure the passwords for SQL logins with sysadmin privileges are
    changed on a frequent basis to help prevent compromise via a brute force attack. CONTROL SERVER is an equivalent permission to sysadmin and logins with that permission should
    also be required to have expiring passwords.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("4.2")
    $obj | Add-Member NoteProperty Task("Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role")

    $query = "SELECT l.[name], 'sysadmin membership' AS 'Access_Method'
                FROM sys.sql_logins AS l
                WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1
                AND l.is_expiration_checked <> 1
                UNION ALL
                SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method'
                FROM sys.sql_logins AS l
                JOIN sys.server_permissions AS p
                ON l.principal_id = p.grantee_principal_id
                WHERE p.type = 'CL' AND p.state IN ('G', 'W')
                AND l.is_expiration_checked <> 1;"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }
        [string]$s = $null
        $s = $sqlResult -join ", "

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Found missmatching account(s): " + $s.name)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLCheckPolicyOptionOn {
    <#
.Synopsis
    Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins.
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 4  Password Policies

    4.3 - Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins.

    Applies the same password complexity policy used in Windows to passwords used inside SQL Server.

    Ensure SQL authenticated login passwords comply with the secure password policy applied by the Windows Server Benchmark so that they cannot be easily compromised via brute
    force attack.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("4.3")
    $obj | Add-Member NoteProperty Task("Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins")

    $query = "SELECT name, is_disabled
                FROM sys.sql_logins
                WHERE is_policy_checked = 0;"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ( $null -eq $sqlResult ) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Found missmatching account(s):" + $sqlResult.name)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}
#endregion

#region 5 Auditing and Logging
#
#This section contains recommendations related to SQL Server's audit and logging mechanisms.
#

function Test-SQLMaximumNumberOfErrorLogFiles {
    <#
    .Synopsis
        Ensure 'Maximum number of error log files' is set to greater than or equal to '12'
    .DESCRIPTION
        CIS SQL Server 2016 Benchmark - 5 Auditing and Logging

        5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12'

        SQL Server error log files must be protected from loss. The log files must be backed up before they are overwritten. Retaining more error logs helps prevent loss from frequent recycling before backups can occur.

        The SQL Server error log contains important information about major server events and login attempt information as well.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("5.1")
    $obj | Add-Member NoteProperty Task("Ensure 'Maximum number of error log files' is set to greater than or equal to '12'")

    $query = "DECLARE @NumErrorLogs int;
    EXEC master.sys.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'NumErrorLogs', @NumErrorLogs OUTPUT;
     SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        $numberOfLogFiles = $sqlResult.NumberOfLogFiles

        if ($numberOfLogFiles -ge 12) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Maximum number of error log files is set to $numberOfLogFiles")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLDefaultTraceEnabled {
    <#
    .Synopsis
        Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'
    .DESCRIPTION
        CIS SQL Server 2016 Benchmark - 5 Auditing and Logging

        5.2 Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'

        The default trace provides audit logging of database activity including account creations, privilege elevation and execution of DBCC commands.

        Default trace provides valuable audit information regarding security-related activities on the server.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("5.2")
    $obj | Add-Member NoteProperty Task("Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'")

    $query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use
    FROM sys.configurations
    WHERE name = 'default trace enabled';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if (($sqlResult.value_configured -eq 1) -and ($sqlResult.value_in_use -eq 1)) {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("Maximum number of error log files too high")
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLLoginAuditingIsSetToFailedLogins {
    <#
    .Synopsis
        Ensure 'Login Auditing' is set to 'failed logins'
    .DESCRIPTION
        CIS SQL Server 2016 Benchmark - 5 Auditing and Logging

        5.3 Ensure 'Login Auditing' is set to 'failed logins'

        This setting will record failed authentication attempts for SQL Server logins to the SQL Server Errorlog. This is the default setting for SQL Server.
        Default trace provides valuable audit information regarding security-related activities on the server.
        Historically, this setting has been available in all versions and editions of SQL Server. Prior to the availability of SQL Server Audit, this was the only provided mechanism for capturing logins (successful or failed).

        Capturing failed logins provides key information that can be used to detect\confirm password guessing attacks. Capturing successful login attempts can be used to confirm server access during forensic investigations, but using this audit level setting to also capture successful logins creates excessive noise in the SQL Server Errorlog which can hamper a DBA trying to troubleshoot problems. Elsewhere in this benchmark, we recommend using the newer lightweight SQL Server Audit feature to capture both successful and failed logins.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("5.3")
    $obj | Add-Member NoteProperty Task("Ensure 'Login Auditing' is set to 'failed logins'")

    $query = "EXEC xp_loginconfig 'audit level';"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        if ($sqlResult.config_value -eq "failure") {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
        else {
            $obj | Add-Member NoteProperty Status("config_value is set to: " + $sqlResult.config_value)
            $obj | Add-Member NoteProperty Audit("False")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}

function Test-SQLLoginAuditingIsSetToFailedAndSuccessfulLogins {
    <#
    .Synopsis
        Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'
    .DESCRIPTION
        CIS SQL Server 2016 Benchmark - 5 Auditing and Logging

        5.4 Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'

        SQL Server Audit is capable of capturing both failed and successful logins and writing them to one of three places: the application event log, the security event log, or the file system. We will use it to capture any login attempt to SQL Server, as well as any attempts to change audit policy. This will also serve to be a second source to record failed login attempts.

        By utilizing Audit instead of the traditional setting under the Security tab to capture successful logins, we reduce the noise in the ERRORLOG. This keeps it smaller and easier to read for DBAs who are attempting to troubleshoot issues with the SQL Server. Also, the Audit object can write to the security event log, though this requires operating system configuration. This gives an additional option for where to store login events, especially in conjunction with an SIEM.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("5.4")
    $obj | Add-Member NoteProperty Task("Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'")

    $query = "SELECT
    S.name AS 'Audit Name'
    , CASE S.is_state_enabled
    WHEN 1 THEN 'Y'
    WHEN 0 THEN 'N' END AS 'Audit Enabled'
    , S.type_desc AS 'Write Location'
    , SA.name AS 'Audit Specification Name'
    , CASE SA.is_state_enabled
    WHEN 1 THEN 'Y'
    WHEN 0 THEN 'N' END AS 'Audit Specification Enabled'
    , SAD.audit_action_name
    , SAD.audited_result
    FROM sys.server_audit_specification_details AS SAD
    JOIN sys.server_audit_specifications AS SA
    ON SAD.server_specification_id = SA.server_specification_id
    JOIN sys.server_audits AS S
    ON SA.audit_guid = S.audit_guid
    WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD');
    GO"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        $auditSpecifications = @()
        foreach ($sqlResult in $sqlResults) {
            switch ($sqlResult.audit_action_name) {
                "AUDIT_CHANGE_GROUP" {
                    $auditSpecifications += ($sqlResult)
                }
                "FAILED_LOGIN_GROUP" {
                    $auditSpecifications += ($sqlResult)
                }
                "SUCCESSFUL_LOGIN_GROUP" {
                    $auditSpecifications += ($sqlResult)
                }
                Default {}
            }
        }
        $foundSpecifications = @()
        foreach ($auditSpecification in $auditSpecifications) {
            if ((($auditspecification | Select-Object -ExpandProperty "Audit Enabled") -ne "Y") -or `
                (($auditspecification | Select-Object -ExpandProperty "Audit Specification Enabled") -ne "Y") -or `
                ($auditspecification.audited_result -ne "SUCCESS AND FAILURE")) {
                $foundSPecifications += $auditSpecification.audit_action_name
            }
        }
        if ($null -eq $sqlResults) {
            $obj | Add-Member NoteProperty Status("TrackLogins file not found")
            $obj | Add-Member NoteProperty Audit("Warning")
        }
        else {
            if ($foundSpecifications.count -eq 0) {
                $obj | Add-Member NoteProperty Status("All good")
                $obj | Add-Member NoteProperty Audit("True")
            }
            else {
                [string]$s = $null
                $s = $foundSpecifications -join ", "
                $obj | Add-Member NoteProperty Status("Found following specifications: $s")
                $obj | Add-Member NoteProperty Audit("False")
            }
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }

    Write-Output $obj
}
#endregion

#region 6 Application Development
#
# This section contains recommendations related to developing applications that interface with SQL Server.
#
function Test-CLRAssemblyPermissionSet {
    <#
.Synopsis
    Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies
.DESCRIPTION
    CIS SQL Server 2016 Benchmark - 6  Application Development

    6.2 - Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies.

    Setting CLR Assembly Permission Sets to SAFE_ACCESS will prevent assemblies from accessing external system resources such as files, the network, environment variables, or the registry.

    Assemblies with EXTERNAL_ACCESS or UNSAFE permission sets can be used to access sensitive areas of the operating system, steal and/or transmit data and alter the state and other protection measures of the underlying Windows Operating System. Assemblies which are Microsoft-created (is_user_defined = 0) are excluded from this check as they are required for overall system functionality.
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("6.2")
    $obj | Add-Member NoteProperty Task("Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies")

    $query = "SELECT name,
                permission_set_desc
                FROM sys.assemblies
                where is_user_defined = 1;"

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $assemblies = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
        }
        else {
            $assemblies = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
        }

        $unSafeAssemblies = @()
        foreach ($assembly in $assemblies) {
            if ($assembly.permission_set_desc -ne "SAFE_ACCESS") {
                $unSafeAssemblies += $assembly
            }
        }
        if ($unSafeAssemblies.Count -gt 0 ) {
            $obj | Add-Member NoteProperty Status("Found unsafe assmblies: " + $unSafeAssemblies)
            $obj | Add-Member NoteProperty Audit("False")
        }
        else {
            $obj | Add-Member NoteProperty Status("All good")
            $obj | Add-Member NoteProperty Audit("True")
        }
    }
    catch [System.Data.SqlClient.SqlException] {
        $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
        $obj | Add-Member NoteProperty Audit("Warning")
    }

    Write-Output $obj
}
#endregion

#region 7 Encryption
#
# These recommendations pertain to encryption-related aspects of SQL Server.
#
function Test-SQLSymmetricKeyEncryptionAlgorithm {
    <#
    .Synopsis
        Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases
    .DESCRIPTION
        CIS SQL Server 2016 Benchmark - 7 Encryption

        7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases

        Per the Microsoft Best Practices, only the SQL Server AES algorithm options, AES_128, AES_192, and AES_256, should be used for a symmetric key encryption algorithm.

        The following algorithms (as referred to by SQL Server) are considered weak or deprecated and should no longer be used in SQL Server: DES, DESX, RC2, RC4, RC4_128.
        Many organizations may accept the Triple DES algorithms (TDEA) which use keying options 1 (3 key aka 3TDEA) or keying option 2 (2 key aka 2TDEA). In SQL Server, these are referred to as TRIPLE_DES_3KEY and TRIPLE_DES respectively. Additionally, the SQL Server algorithm named DESX is actually the same implementation as the TRIPLE_DES_3KEY option. However, using the DESX identifier as the algorithm type has been deprecated and its usage is now discouraged.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $databases = Get-SqlDatabase -ServerInstance $InstanceName -ErrorAction Stop | Where-Object {$_.IsSystemObject -ne "true"} | Select-Object -ExpandProperty name
        }
        else {
            $databases = Get-SqlDatabase -ServerInstance $MachineName -ErrorAction Stop | Where-Object {$_.IsSystemObject -ne "true"} | Select-Object -ExpandProperty name
        }

        if ($databases.Count -eq 0) {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty ID("7.1")
            $obj | Add-Member NoteProperty Task("Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases")
            $obj | Add-Member NoteProperty Status("No databases found")
            $obj | Add-Member NoteProperty Audit("True")
            return $obj
        }
        $index = 1

        foreach ($database in $databases) {

            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty ID("7.1.$index")
            $obj | Add-Member NoteProperty Task("Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher for database $database")


            $query = "USE [$database]
            GO
            SELECT db_name() AS db_name, name AS Key_Name
            FROM sys.symmetric_keys
            WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256')
            AND db_id() > 4;
            GO"

            try {
                if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
                }
                else {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
                }

                if ( $null -eq $sqlResult ) {
                    $obj | Add-Member NoteProperty Status("All good")
                    $obj | Add-Member NoteProperty Audit("True")
                }
                else {
                    $obj | Add-Member NoteProperty Status("Got $sqlResult")
                    $obj | Add-Member NoteProperty Audit("False")
                }
            }
            catch [System.Data.SqlClient.SqlException] {
                $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
                $obj | Add-Member NoteProperty Audit("Warning")
            }


            Write-Output $obj

            $index++
        }
    }
    catch {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty ID("7.1")
        $obj | Add-Member NoteProperty Task("Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases")
        $obj | Add-Member NoteProperty Status("Failed to connect to server $instanceName")
        $obj | Add-Member NoteProperty Audit("Warning")
        Write-Output $obj
    }
}

function Test-SQLAsymmetricKeySize {
    <#
    .Synopsis
        Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases
    .DESCRIPTION
        CIS SQL Server 2016 Benchmark - 7 Encryption

        7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases

        Microsoft Best Practices recommend to use at least a 2048-bit encryption algorithm for asymmetric keys.

        The RSA_2048 encryption algorithm for asymmetric keys in SQL Server is the highest bitlevel provided and therefore the most secure available choice (other choices are RSA_512 and RSA_1024).
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME,

        [string] $InstanceName = "$machineName\$sqlInstance"
    )

    try {
        if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
            $databases = Get-SqlDatabase -ServerInstance $InstanceName -ErrorAction Stop | Where-Object {$_.IsSystemObject -ne "true"} | Select-Object -ExpandProperty name
        }
        else {
            $databases = Get-SqlDatabase -ServerInstance $MachineName -ErrorAction Stop | Where-Object {$_.IsSystemObject -ne "true"} | Select-Object -ExpandProperty name
        }

        if ($databases.Count -eq 0) {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty ID("7.2")
            $obj | Add-Member NoteProperty Task("Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases")
            $obj | Add-Member NoteProperty Status("No databases found")
            $obj | Add-Member NoteProperty Audit("True")
            return $obj
        }

        $index = 1

        foreach ($database in $databases) {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty ID("7.2.$index")
            $obj | Add-Member NoteProperty Task("Ensure CONNECT permissions on the 'guest' user is revoked for database $database")

            $query = "USE [$database]
            GO
            SELECT db_name() AS db_name, name AS Key_Name
            FROM sys.symmetric_keys
            WHERE key_length < 2048
            AND db_id() > 4;
            GO"

            try {
                if ($PsCmdlet.ParameterSetName -eq "ByInstance" -and $sqlInstance -ne "MSSQLSERVER") {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $instanceName -ErrorAction Stop
                }
                else {
                    $sqlResult = Invoke-Sqlcmd -Query $query -ServerInstance $MachineName -ErrorAction Stop
                }
                if ( $null -eq $sqlResult ) {
                    $obj | Add-Member NoteProperty Status("All good")
                    $obj | Add-Member NoteProperty Audit("True")
                }
                else {
                    $obj | Add-Member NoteProperty Status("Got $sqlResult")
                    $obj | Add-Member NoteProperty Audit("False")
                }
            }
            catch [System.Data.SqlClient.SqlException] {
                $obj | Add-Member NoteProperty Status("Server Instance not found or accessible")
                $obj | Add-Member NoteProperty Audit("Warning")
            }


            Write-Output $obj

            $index++
        }

    }
    catch {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty ID("7.2")
        $obj | Add-Member NoteProperty Task("Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases")
        $obj | Add-Member NoteProperty Status("Failed to connect to server $instanceName")
        $obj | Add-Member NoteProperty Audit("Warning")
        Write-Output $obj
    }
}

#endregion

#region 8 Appendix: Additional Considerations
#
# This appendix discusses possible configuration options for which no recommendation is being given.
#
function Test-SQLServerBrowserService {
    <#
    .Synopsis
        Ensure 'SQL Server Browser Service' is configured correctly
    .DESCRIPTION
        CIS SQL Server 2016 Benchmark - 8 Appendix: Additional Considerations

        8.1 Ensure 'SQL Server Browser Service' is configured correctly

        No recommendation is being given on disabling the SQL Server Browser service.
    #>
    [CmdletBinding()]

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ID("8.1")
    $obj | Add-Member NoteProperty Task("Ensure 'SQL Server Browser Service' is configured correctly")

    try {
        $sqlBrowserService = Get-Service -name 'sqlbrowser'

        if ($sqlBrowserService.Status -eq 'stopped') {
            if ($sqlBrowserService.StartType -eq 'Disabled') {
                $obj | Add-Member NoteProperty Status("All good")
                $obj | Add-Member NoteProperty Audit("True")
            }
            else {
                $obj | Add-Member NoteProperty Status("StartType: Enabled")
                $obj | Add-Member NoteProperty Audit("Warning")
            }
        }
        else {
            $obj | Add-Member NoteProperty Audit("False")
            if ($sqlBrowserService.StartType -eq 'Disabled') {
                $obj | Add-Member NoteProperty Status("SQL Server Browser is running")
            }
            else {
                $obj | Add-Member NoteProperty Status("SQL Server Browser is running and StartType: Enabled")
            }
        }
    }
    catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        $obj | Add-Member NoteProperty Status("Connot find any service with service name 'sqlbrowser'")
        $obj | Add-Member NoteProperty Audit("Warning")
    }
    Write-Output $obj
}
#endregion

#region Hyperfunctions
function Convert-ToAuditInfo {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Psobject] $auditObject
    )

    process {
        Write-Output @{
            Id      = $auditObject.ID
            Task    = $auditObject.Task
            Message = $auditObject.Status
            Status   = $auditObject.Audit
        }
    }
}
#endregion

#region Reportgeneration
function Get-SQL2016AuditInfos {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByInstance")]
        [string] $SqlInstance,

        [string] $MachineName = $env:COMPUTERNAME
    )

    switch ($PsCmdlet.ParameterSetName) {
        "ByInstance" {
            $sqlInstances = $sqlInstance
            break
        }
        "Default" {
            $smo = 'Microsoft.SqlServer.Management.Smo.'
            $wmi = New-Object ($smo + 'Wmi.ManagedComputer')
            $singleWmi = $wmi | Where-Object { $_.Name -eq $machineName }
            $sqlServer = $singleWmi.Services | Where-Object { $_.Type -eq "SqlServer" }
            $sqlInstances = $sqlServer `
                | Foreach-Object { $_.Name.Substring($_.Name.IndexOf('$') + 1) } `
                #    | Where-Object { $_ -ne "MSSQLSERVER" }
        }
    }

    $InstanceAudits = @()
    foreach ($sqlInstance in $sqlInstances) {
        $auditInfos = @()

        # Section 2
        $auditInfos += Test-SQLAdHocDistributedQueriesDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLClrEnabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLCrossDBOwnershipDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLDatabaseMailXPsDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLOleAutomationProceduresDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLRemoteAccessDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLRemoteAdminConnectionsDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLScanForStartupProcsDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLTrustworthyDatabaseOff -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLServerProtocolsDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLUseNonStandardPorts -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLHideInstanceEnabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLSaLoginAccountDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLSaLoginAccountRenamed -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLXpCommandShellDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLAutoCloseOff -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLNoSaAccounnt -MachineName $machineName -SqlInstance $sqlInstance

        # Section 3
        $auditInfos += Test-SQLServerAuthentication -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLGuestPermissionOnDatabases -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLDropOrphanedUsers -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLAuthenticationDisabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLServerServiceAccountIsNotAnAdministrator -MachineName $machineName
        $auditInfos += Test-SQLAgentServiceAccountIsNotAnAdministrator -MachineName $machineName
        $auditInfos += Test-SQLFullTextServiceAccountIsNotAnAdministrator -MachineName $machineName
        $auditInfos += Test-SQLPermissionsForRolePublic -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLWindowsBuiltinNoSqlLogin -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLWindowsLocalGroupsNoSqlLogin -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLPublicRoleMsdbDatabase -MachineName $machineName -SqlInstance $sqlInstance

        # Section 4
        $auditInfos += Test-SQLMustChangeOptionIsOn -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLCheckExpirationOptionOn -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLCheckPolicyOptionOn -MachineName $machineName -SqlInstance $sqlInstance

        # Section 5
        $auditInfos += Test-SQLMaximumNumberOfErrorLogFiles -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLDefaultTraceEnabled -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLLoginAuditingIsSetToFailedLogins -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLLoginAuditingIsSetToFailedAndSuccessfulLogins -MachineName $machineName -SqlInstance $sqlInstance

        # Section 6
        $auditInfos += Test-CLRAssemblyPermissionSet -MachineName $machineName -SqlInstance $sqlInstance

        # Section 7
        $auditInfos += Test-SQLSymmetricKeyEncryptionAlgorithm -MachineName $machineName -SqlInstance $sqlInstance
        $auditInfos += Test-SQLAsymmetricKeySize -MachineName $machineName -SqlInstance $sqlInstance

        # Section 8
        $auditInfos += Test-SQLServerBrowserService

        $InstanceAudits += @{
            InstanceName = $sqlInstance
            AuditInfos   = $auditInfos | Convert-ToAuditInfo
        }
    }

    return $InstanceAudits
}

switch ($PsCmdlet.ParameterSetName) {
    "ByInstance" {
        $InstanceAudits = (Get-SQL2016AuditInfos -SqlInstance $sqlInstance -MachineName $machineName)
        break
    }
    "ByAuditInfo" {
        break
    }
    "Default" {
        $InstanceAudits = (Get-SQL2016AuditInfos)
    }
}

[Report] @{
    Title = "SQL 2016 Benchmarks"
    ModuleName = "ATAPAuditor"
    BasedOn = "CIS Microsoft SQL Server 2016 Benchmark, Version: 1.0.0, Date: 2017-11-08"
    Sections = @(
        foreach ($InstanceAudit in $InstanceAudits) {
            [ReportSection] @{
                Title = $InstanceAudit.InstanceName
                Description = "This section contains the audits for the sqlInstance $($InstanceAudit.InstanceName)"
                SubSections = @(
                    [ReportSection] @{
                        Title = "2 Surface Area Reduction"
                        Description = "SQL Server offers various configuration options, some of them can be controlled by the sp_configure stored procedure. This section contains the listing of the corresponding recommendations."
                        AuditInfos = $InstanceAudit.AuditInfos | Where-Object {$_.Id -like "2.*"}
                    }
                    [ReportSection] @{
                        Title = "3 Authentication and Authorization"
                        Description = "This section contains recommendations related to SQL Server's authentication and authorization mechanisms."
                        AuditInfos = $InstanceAudit.AuditInfos | Where-Object {$_.Id -like "3.*"}
                    }
                    [ReportSection] @{
                        Title = "4 Password Policies"
                        Description = "This section contains recommendations related to SQL Server's password policies."
                        AuditInfos = $InstanceAudit.AuditInfos | Where-Object {$_.Id -like "4.*"}
                    }
                    [ReportSection] @{
                        Title = "5 Auditing and Logging"
                        Description = "This section contains recommendations related to SQL Server's audit and logging mechanisms."
                        AuditInfos = $InstanceAudit.AuditInfos | Where-Object {$_.Id -like "5.*"}
                    }
                    [ReportSection] @{
                        Title = "6 Application Development"
                        Description = "This section contains recommendations related to developing applications that interface with SQL Server."
                        AuditInfos = $InstanceAudit.AuditInfos | Where-Object {$_.Id -like "6.*"}
                    }
                    [ReportSection] @{
                        Title = "7 Encryption"
                        Description = "These recommendations pertain to encryption-related aspects of SQL Server."
                        AuditInfos = $InstanceAudit.AuditInfos | Where-Object {$_.Id -like "7.*"}
                    }
                    [ReportSection] @{
                        Title = "8 Appendix: Additional Considerations"
                        Description = "This appendix discusses possible configuration options for which no recommendation is being given."
                        AuditInfos = $InstanceAudit.AuditInfos | Where-Object {$_.Id -like "8.*"}
                    }
                )
            }
        }
    )
}
#endregion
