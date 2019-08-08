<#
.SYNOPSIS
Do Proxy Auth with Default Network Credential

.DESCRIPTION
Do Proxy Auth with Default Network Credential

.EXAMPLE
Get-AuthProxy

.NOTES
TODO - Add More scenario and add this as a option to other Function
#>

Function Get-AuthProxy
{
	[CmdletBinding()]
	param (

	)
    #Do Proxy Auth with Default Network Credential
    $wc = New-Object System.Net.WebClient
    $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
}
