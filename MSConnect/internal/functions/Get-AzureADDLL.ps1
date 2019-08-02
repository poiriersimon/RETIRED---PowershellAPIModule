Function Get-AzureADDLL
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [Switch]
        $InstallPreview
    )
    [array]$AzureADModules = Get-Module -ListAvailable | where{$_.name -eq "AzureAD" -or $_.name -eq "AzureADPreview"}
    Try
    {
        if($AzureADModules.count -eq 0 -and $InstallPreview -eq $True)
        {
            Install-Module AzureADPreview -Confirm:$False -Force
        }
        elseif($AzureADModules.count -eq 0)
        {
            Install-Module AzureAD -Confirm:$False -Force
        }
    }
    Catch
    {
        Throw "Can't find Azure AD DLL. Install the module manually 'Install-Module AzureAD'"
    }

    $AzureDLL = join-path (($AzureADModules | sort version -Descending | Select -first 1).Path | split-Path) Microsoft.IdentityModel.Clients.ActiveDirectory.dll
    Return $AzureDLL
}
