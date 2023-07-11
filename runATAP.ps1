#set the directory where you want to save the reports
$report_directory = "C:\Users\Frick\Documents\ATAPReports"
#enter which report you want to execute
$report_name = "Microsoft Windows 10"
#saves old working directory
$old_pwd = $pwd

#to access the report file later, "Microsoft" has to be cut out of the String
if($report_name.Contains("Microsoft")) {
    $report = $report_name.Substring(10, ($report_name.Length-10))
}
else {
    $report = $report_name
}

#starts generating the HTML report
Save-ATAPHtmlReport $report_name -Path $report_directory -MITRE

#enters the report_directory and searchs for the newest report of the kind set above
cd $report_directory
if ((ls -Name) -eq $null) {
    echo 'Error no report could be generated.'
}
elseif((ls -Name).GetType().Name -eq 'String') {
    $file = ls -Name
    #opens the report with the standard appplication set in windows
    Start-Process -FilePath $file
    #goes back to the old working directory
    cd $old_pwd
}
elseif((ls -Name).GetType().Name -eq 'Object[]') {
    $i = ((ls -Name).Length)-1
    $file = $report_directory + "\" + (ls -Name)[$i]
    while(!$file.Contains($report)) {
        $i = $i - 1
        $file = $report_directory + "\" + (ls -Name)[$i]
    }
    #opens the report with the standard appplication set in windows
    Start-Process -FilePath $file
    #goes back to the old working directory
    cd $old_pwd
}