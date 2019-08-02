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
