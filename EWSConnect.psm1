#Requires -Version 5.0
################################################################################# 
#  
# The sample scripts are not supported under any Microsoft standard support  
# program or service. The sample scripts are provided AS IS without warranty  
# of any kind. Microsoft further disclaims all implied warranties including, without  
# limitation, any implied warranties of merchantability or of fitness for a particular  
# purpose. The entire risk arising out of the use or performance of the sample scripts  
# and documentation remains with you. In no event shall Microsoft, its authors, or  
# anyone else involved in the creation, production, or delivery of the scripts be liable  
# for any damages whatsoever (including, without limitation, damages for loss of business  
# profits, business interruption, loss of business information, or other pecuniary loss)  
# arising out of the use of or inability to use the sample scripts or documentation,  
# even if Microsoft has been advised of the possibility of such damages 
# 
################################################################################# 

<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.PARAMETER InstallPreview
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>

Function Get-EWSDLL
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [Switch]
        $AllowInstall,
        [Parameter(Mandatory = $false)]
        [System.String]
        $EWSDLLPath = "C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll"

    )
    if((Test-Path $EWSDLLPath) -eq $False -and $AllowInstall -eq $True)
    {
        $request = Invoke-WebRequest -Uri https://www.microsoft.com/en-us/download/confirmation.aspx?id=42951
        Invoke-WebRequest -Uri $(($request.Links |where {$_.href -like "*.msi*"}).href) -Outfile $(Joint-path $PSScriptRoot "EwsManagedApi.msi")
        #Install MSI Based On : https://powershellexplained.com/2016-10-21-powershell-installing-msi-files/
        $File = Get-item $(Joint-path $PSScriptRoot "EwsManagedApi.msi")
        $DataStamp = get-date -Format yyyyMMddTHHmmss
        $logFile = '{0}-{1}.log' -f $file.fullname,$DataStamp
        $MSIArguments = @(
            "/i"
            ('"{0}"' -f $file.fullname)
            "/qn"
            "/norestart"
            "/L*v"
            $logFile
        )
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 
        Start-sleep -Seconds 15
        Remove-Item $file.FullName
        if((Test-Path $EWSDLLPath) -eq $False){
            Write-Error "Can't find EWS API. Please install it manually https://www.microsoft.com/en-us/download/confirmation.aspx?id=42951"
            return
        }
    }
    Elseif((Test-Path $EWSDLLPath) -eq $False -and $AllowInstall -eq $False)
    {
        Write-Error "Can't find EWS API. Please install it manually https://www.microsoft.com/en-us/download/confirmation.aspx?id=42951"
        return
    }
    ##Load EWS DLL
    Return $EWSDLLPath
    
}

## Connect EWS
# User + Impersonnation + App


# Call EWS
