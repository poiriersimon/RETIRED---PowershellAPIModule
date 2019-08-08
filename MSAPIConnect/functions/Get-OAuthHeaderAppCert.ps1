<#
.SYNOPSIS
Authenticate to Azure AD with Azure Directory Authentication Librairy for an Azure Ad Application leveraging Certificate Authentication

.DESCRIPTION
Authenticate to Azure AD with Azure Directory Authentication Librairy for an Azure Ad Application leveraging Certificate Authentication

.PARAMETER ClientID
This is the Client ID (Application ID) of the registered Azure AD Application.
The Application need to have the right permission in your tenant.

.PARAMETER CertificatePath
If you are leveraging an Azure AD Application with Certificate authentication, you need to provide the Certificate Path here

.PARAMETER CertificatePassword
If you are leveraging an Azure AD Application with Certificate authentication, you need to provide the Certificate Password here to access the private key

.PARAMETER TenantName
You need to specify the Tenant Name, Tenant ID or Registered Domain name on your Azure or Office 365 Tenant

.PARAMETER ResourceURI
Resource URI of the Azure AD Application that is registered.

.EXAMPLE
TODO - Example
TODO - Line 2

.NOTES
#TODO : Check for to add thumbprint option for installed certificate
#>

Function Get-OAuthHeaderAppCert
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param (
    [cmdletbinding()]
    [parameter(Mandatory=$true)]
        $ClientID,
    [parameter(Mandatory=$true)]
        $CertificatePath,
    [parameter(Mandatory=$true)]
        $CertificatePassword,
    [parameter(Mandatory=$true)]
        $TenantName,
    [Parameter(Mandatory = $True)]
      	[string]$ResourceURI
    )
    $TenantName = Test-TenantName -TenantName $TenantName
    $AzureADDLL = Get-AzureADDLL

    #Load Certificate
    $flag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    $AppCert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword, $flag )

    #Login Endpoint info
    $authority = ($(Get-TenantLoginEndPoint -TenantName $TenantName)).authorization_endpoint

    #Can't sideload the DLL for this one since the AppCert isn't pass correclty.
    $NULL = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
    # Create Authentication Context tied to Azure AD Tenant
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $cac = New-Object  Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate($clientID, $AppCert)
    Try{
        $authResult = $authContext.AcquireTokenSilentAsync($resourceAppIdURI, $clientId)
        $AuthHeader=$authResult.result.CreateAuthorizationHeader()
    }
    Catch{
        $authResult = $authContext.AcquireTokenASync($resourceURI, $cac)
        if ($authResult.IsFaulted -eq $True)
        {
            Throw "No Access Token"
        }
        else
        {
            $AuthHeader=$authResult.result.CreateAuthorizationHeader()
        }
    }

    # Perform REST call.
        $headers = @{
            "Authorization" = $AuthHeader
            "Content-Type"  = "application/json"
            "ExpiresOn"     = $authResult.Result.ExpiresOn
            "AppID"     = $ClientID
        }
    Return $headers

}
