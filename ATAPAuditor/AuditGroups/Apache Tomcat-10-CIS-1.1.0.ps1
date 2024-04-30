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
    if (GetCatalinaHome -match "") {
        return false
    } else {
        return true
    }
}

# return the value of $CATALINA_HOME
function GetCatalinaHome{
    $cat = echo $CATALINA_HOME
    $stat = $?
    if ($stat -eq 0) {
        return $cat
    } else {
        return ""
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
        $dir1 = ls -l $CATALINA_HOME/webapps/examples
        $stat1 = $?
        $dir2 = ls -l $CATALINA_HOME/webapps/docs
        $stat2 = $?
        $dir3 = ls -l $CATALINA_HOME/webapps/ROOT
        $stat3 = $?
        $dir4 = ls -l $CATALINA_HOME/webapps/host-manager
        $stat4 = $?
        $dir5 = ls -l $CATALINA_HOME/webapps/manager
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

### TODO
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

###TODO
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
