<#
.SYNOPSIS
Send a Web Request to retrieve well known Tenant Login endpoint

.DESCRIPTION
Send a Web Request to retrieve well known Tenant Login endpoint

.PARAMETER TenantName
You need to specify the Tenant Name, Tenant ID or Registered Domain name on your Azure or Office 365 Tenant

.PARAMETER LoginSource
You can choose to leverage EvoSTS (work with both On-Premises and Azure AD) or MicrosoftOnline (Cloud Only)

.EXAMPLE
Retrieve the Autorization Endpoint for the tenant contoso.com
Get-TenantLoginEndPoint -TenantName contoso.com | Select authorization_endpoint

.NOTES
#
#>

Function Get-TenantLoginEndPoint
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $TenantName,
        [Parameter(Mandatory = $false)]
        [System.String]
        [ValidateSet('MicrosoftOnline','EvoSTS')]
        $LoginSource = "EvoSTS"
    )
    $TenantInfo = @{}
    if($LoginSource -eq "EvoSTS")
    {
        $webrequest = Invoke-WebRequest -Uri https://login.windows.net/$($TenantName)/.well-known/openid-configuration -UseBasicParsing
    }
    else {
        $webrequest = Invoke-WebRequest -Uri https://login.microsoftonline.com/$($TenantName)/.well-known/openid-configuration -UseBasicParsing
    }
    if($webrequest.StatusCode -eq 200){
        $TenantInfo = $webrequest.Content |ConvertFrom-Json
    }
    Return $TenantInfo
}
