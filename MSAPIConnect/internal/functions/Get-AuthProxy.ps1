Function Get-AuthProxy
{
	[CmdletBinding()]
	param (

	)
    #Do Proxy Auth with Default Network Credential
    $wc = New-Object System.Net.WebClient
    $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
}
