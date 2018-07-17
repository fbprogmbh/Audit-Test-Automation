<#
Copyright (c) 2017, FB Pro GmbH, Germany
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

<#

    Author(s):        Dennis Esly 
    Date:             05/01/2017
    Last change:      05/02/2017
    Version:          1.0

#>


function Set-LogFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Alias('LogPath')]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [Alias('Logname')]
        [string]$Name
    )


    $FullPath = get-FullPath $Path $Name

    # Create file if it does not already exists 
    if (!(Test-Path -Path $FullPath)){
        
        # Create file and start logging
        New-Item -Path $FullPath -ItemType File -Force | Out-Null

        Add-Content -Path $FullPath -Value "***************************************************************************************************"
        Add-Content -Path $FullPath -Value " Logfile created at [$([DateTime]::Now)]"
        Add-Content -Path $FullPath -Value "***************************************************************************************************"
        Add-Content -Path $FullPath -Value ""
        Add-Content -Path $FullPath -Value "" 
    }
}


function Write-LogFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)] 
        [Alias('LogMessage')] 
        [string]$Message, 

        [Parameter(Mandatory=$true)]
        [Alias('LogPath')]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [Alias('Logname')]
        [string]$Name,

        [ValidateSet("Error","Warning","Info")] 
        [string]$Level = "Info"
    )


    set-LogFile $Path $Name
    $FullPath = get-FullPath $Path $Name

    

    # Format date for log file 
    $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 

    switch($Level)
    { 
        'Error' { 
            Write-Error $Message 
            $LevelText = '[ERROR]:' 
            } 
        'Warning' { 
            Write-Warning $Message 
            $LevelText = '[WARNING]:' 
            } 
        'Info' { 
            Write-Verbose $Message 
            $LevelText = '[INFO]:' 
            } 
    }
    Add-Content $FullPath "$FormattedDate $LevelText"
    Add-Content $FullPath "$Message"
    Add-Content $FullPath "--------------------------" 
    Add-Content $FullPath ""
}


function Get-FullPath
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$File
    )
    
    if ($Path.Length -gt 0)
    {
        if ($Path[$Path.Length-1] -ne "\")
        {
            $FullPath = $Path + "\" + $File
        }
        else
        {
            $FullPath = $Path + $File
        }
    }

    return $FullPath
}
