<#
.SYNOPSIS
Read the Token Cache from Azure Directory Authentication Librairy that are exposed to Powershell

.DESCRIPTION
Read the Token Cache from Azure Directory Authentication Librairy that are exposed to Powershell

.EXAMPLE
Get-TokenCache

.NOTES
Only the exposed Token will be showen, since ADAL V3 isn't exposing the Refresh Token it won't be shown
#>

Function Get-TokenCache
{
	[CmdletBinding()]
	param (

	)
    $AzureADDLL = Get-AzureADDLL
    $tMod = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
    $cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared
    if($cache.count -gt 0){
        Return $cache.ReadItems()
    }
}
