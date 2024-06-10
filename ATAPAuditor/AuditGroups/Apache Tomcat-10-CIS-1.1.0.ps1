$parentPath = Split-Path -Parent -Path $PSScriptRoot
$scriptPath = $parentPath + "/Helpers/ShellScripts/tomcat/"
$rcTrue = "True"
$rcCompliant = "Compliant"
$rcFalse = "False"
$rcNone = "None"
$rcError = "Error"
$rcNonCompliant = "Non-Compliant"
$rcNonCompliantManualReviewRequired = "Manual Review Required"
$rcErrorCatalinaHomeNotFound = "Environment $CATALINA_HOME not found"
$retCompliant = @{
    Message = $rcCompliant
    Status = $rcTrue
}
$retNonCompliant = @{
    Message = $rcNonCompliant
    Status = $rcFalse
}
$retNonCompliantManualReviewRequired = @{
    Message = $rcNonCompliantManualReviewRequired
    Status = $rcNone
}
$retErrorCatalinaHomeNotFound = @{
    Message = $rcErrorCatalinaHomeNotFound
    Status = $rcError
}

# return true, if $CATALINA_HOME is present, false otherwise
function GetCatalinaHomeStatus{
    if (GetCatalinaHome -ne $null) {
        return true
    } else {
        return false
    }
}

# return the value of $CATALINA_HOME
function GetCatalinaHome{
    $cat = echo $CATALINA_HOME
    if ($null -ne $cat) {
        return $cat
    } else {
        return $null
    }
}

# 1 - Remove Extraneous Resources

[AuditTest] @{
    Id = "1.1"
    Task = "Remove extraneous files and directories"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $dir1 = ls $CATALINA_HOME/webapps/examples
        $stat1 = $?
        $dir2 = ls $CATALINA_HOME/webapps/docs
        $stat2 = $?
        $dir3 = ls $CATALINA_HOME/webapps/ROOT
        $stat3 = $?
        $dir4 = ls $CATALINA_HOME/webapps/host-manager
        $stat4 = $?
        $dir5 = ls $CATALINA_HOME/webapps/manager
        $stat5 = $?
        if ($stat1 -eq 0) {
            if ($dir1 -ne "") {
                return $retNonCompliant
            }
        }
        if ($stat2 -eq 0) {
            if ($dir2 -ne "") {
                return $retNonCompliant
            }
        }
        if ($stat3 -eq 0) {
            if ($dir3 -ne "") {
                return $retNonCompliant
            }
        }
        if ($stat4 -eq 0) {
            if ($dir4 -ne "") {
                return $retNonCompliant
            }
        }
        if ($stat5 -eq 0) {
            if ($dir5 -ne "") {
                return $retNonCompliant
            }
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "1.2"
    Task = "Disable unused Connectors"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

# 2 - Limit server platform information leaks

[AuditTest] @{
    Id = "2.1"
    Task = "Alter the advertised server.info String"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "2.2"
    Task = "Alter the advertised server.number String"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "2.3"
    Task = "Alter the advertised server.built Date"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

# TODO - unklar, keine Anweisung laut Audit
[AuditTest] @{
    Id = "2.4"
    Task = "Alter the advertised server.built Date"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retCompliant
    }
}

[AuditTest] @{
    Id = "2.5"
    Task = "Alter the advertised server.built Date"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "2.6"
    Task = "Turn off TRACE"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "2.7"
    Task = "Ensure Sever Header is Modified To Prevent Information Disclosure"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

# 3 - Protect the Shutdown Port

[AuditTest] @{
    Id = "3.1"
    Task = "Set a nondeterministic Shutdown command value"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf
grep 'shutdown[[:space:]]*=[[:space:]]*"SHUTDOWN"' server.xml
'@
        $test = bash -c $script
        if ($test -match "SHUTDOWN") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "3.2"
    Task = "Disable the Shutdown port"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf
grep '<Server[[:space:]]\+[^>]*port[[:space:]]*=[[:space:]]*"-1"' server.xml
'@
        $test = bash -c $script
        if ($test -match "-1") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# 4 - Protect Tomcat Configurations

[AuditTest] @{
    Id = "4.1"
    Task = "Restrict access to $CATALINA_HOME"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME
find . -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.2"
    Task = "Restrict access to $CATALINA_BASE"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME
find . -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.3"
    Task = "Restrict access to Tomcat configuration directory"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf
find . -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.4"
    Task = "Restrict access to Tomcat logs directory"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME
find logs -follow -maxdepth 0 \( -perm /o+rwx -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.5"
    Task = "Restrict access to Tomcat temp directory"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME
find temp -follow -maxdepth 0 \( -perm /o+rwx -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.6"
    Task = "Restrict access to Tomcat bin directory"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME
find bin -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.7"
    Task = "Restrict access to Tomcat web application directory"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME
find webapps -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.8"
    Task = "Restrict access to Tomcat catalina.properties"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf/
find catalina.properties -follow -maxdepth 0 \( -perm /o+rwx,g+rwx,u+x -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.9"
    Task = "Restrict access to Tomcat catalina.policy"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf/
find catalina.policy -follow -maxdepth 0 \( -perm /o+rwx,g+rwx,u+x -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.10"
    Task = "Restrict access to Tomcat context.xml"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf/
find context.xml -follow -maxdepth 0 \( -perm /o+rwx,g+rwx,u+x -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.11"
    Task = "Restrict access to Tomcat logging.properties"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf/
find logging.properties -follow -maxdepth 0 \( -perm /o+rwx,g+rwx,u+x -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.12"
    Task = "Restrict access to Tomcat server.xml"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf/
find server.xml -follow -maxdepth 0 \( -perm /o+rwx,g+rwx,u+x -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.13"
    Task = "Restrict access to Tomcat tomcat-users.xml"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf/
find tomcat-users.xml -follow -maxdepth 0 \( -perm /o+rwx,g+rwx,u+x -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.14"
    Task = "Restrict access to Tomcat web.xml"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf/
find web.xml -follow -maxdepth 0 \( -perm /o+rwx,g+rwx,u+wx -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "4.15"
    Task = "Restrict access to jaspic-providers.xml"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $script = @'
#!/bin/bash
cd $CATALINA_HOME/conf/
find jaspic-providers.xml -follow -maxdepth 0 \( -perm /o+rwx,g+rwx,u+x -o ! -user tomcat_admin -o ! -group tomcat \) -ls
'@
        $test = bash -c $script
        if ($test -match "") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# 5 - Configure Realms

[AuditTest] @{
    Id = "5.1"
    Task = "Use secure Realms"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $realm1 = grep "Realm className" $CATALINA_HOME/conf/server.xml | grep MemoryRealm
        $realm2 = grep "Realm className" $CATALINA_HOME/conf/server.xml | grep JDBCRealm
        $realm3 = grep "Realm className" $CATALINA_HOME/conf/server.xml | grep UserDatabaseRealm
        $realm4 = grep "Realm className" $CATALINA_HOME/conf/server.xml | grep JAASRealm
        if ($realm1 -eq $null -and $realm2 -eq $null -and $realm3 -eq $null -and $realm4 -eq $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "5.2"
    Task = "Use LockOut Realms"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $realm1 = grep "LockOutRealm" $CATALINA_HOME/conf/server.xml
        if ($realm1 -ne $null) {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# 6 - Conncetor Security

[AuditTest] @{
    Id = "6.1"
    Task = "Setup Client-cert Authentication"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "6.2"
    Task = "Ensure SSLEnabled is set to True for Sensitive Connectors"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "6.3"
    Task = "Ensure scheme is set accurately"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "6.4"
    Task = "Ensure secure is set to true only for SSL-enabled Connectors"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "6.5"
    Task = "Ensure 'sslProtocol' is Configured Correctly for Secure Connectors"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

# 7 - Establish and Protect Logging Facilities
# Kapitel 7 braucht bei Zeiten eine Überarbeitung

[AuditTest] @{
    Id = "7.1"
    Task = "Application specific logging"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "7.2"
    Task = "Specify file handler in logging.properties files"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "7.3"
    Task = "Ensure className is set correctly in context.xml"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "7.4"
    Task = "Ensure directory in context.xml is a secure location"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "7.5"
    Task = "Ensure pattern in context.xml is correct"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "7.6"
    Task = "Ensure directory in logging.properties is a secure location"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

# 8 - Configure Catalina Policy

[AuditTest] @{
    Id = "8.1"
    Task = "Restrict runtime access to sensitive packages"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

# 9 - Application Deployment

[AuditTest] @{
    Id = "9.1"
    Task = "Starting Tomcat with Security Manager"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "9.2"
    Task = "Disabling auto deployment of applications"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $realm1 = grep "autoDeploy" $CATALINA_HOME/conf/server.xml
        if ($realm1 -match "false") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

[AuditTest] @{
    Id = "9.3"
    Task = "Disable deploy on startup of applications"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        $realm1 = grep "deployOnStartup" $CATALINA_HOME/conf/server.xml
        if ($realm1 -match "false") {
            return $retCompliant
        } else {
            return $retNonCompliant
        }
    }
}

# 10 - Miscellaneous Configuration Settings

[AuditTest] @{
    Id = "10.1"
    Task = "Ensure Web content directory is on a separate partition from the Tomcat system files"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.2"
    Task = "Restrict access to the web administration application"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.3"
    Task = "Restrict manager application"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.4"
    Task = "Force SSL when accessing the manager application via HTTP"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.5"
    Task = "Rename the manager application"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.6"
    Task = "Enable strict servlet Compliance"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.7"
    Task = "Turn off session facade recycling"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.8"
    Task = "Do not allow additional path delimiters"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.9"
    Task = "Configure connectionTimeout"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.10"
    Task = "Configure maxHttpHeaderSize"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.11"
    Task = "Force SSL for all applications"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.12"
    Task = "Do not allow symbolic linking"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.13"
    Task = "Do not run applications as privileged"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.14"
    Task = "Do not allow cross context requests"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.15"
    Task = "Do not resolve hosts on logging valves"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.16"
    Task = "Enable memory leak listener"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.17"
    Task = "Setting Security Lifecycle Listener"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.18"
    Task = "Use the logEffectiveWebXml and metadata-complete settings for deploying applications in production"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}

[AuditTest] @{
    Id = "10.19"
    Task = "Ensure Manager Application Passwords are Encrypted"
    Test = {
        if (GetCatalinaHomeStatus -eq $false) {
            return $rcErrorCatalinaHomeNotFound
        }
        return $retNonCompliantManualReviewRequired
    }
}