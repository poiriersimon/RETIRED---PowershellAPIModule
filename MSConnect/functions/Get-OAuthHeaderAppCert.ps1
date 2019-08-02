Function Get-OAuthHeaderAppCert
{
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
      	[string]$resourceURI
    )
    $TenantName = Test-TenantName -TenantName $TenantName
    $AzureADDLL = Get-AzureADDLL

    #Load Certificate
    $flag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    $AppCert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword, $flag )
    
    #Login Endpoint info
    $authority = ($(Get-TenantLoginEndPoint -TenantName $TenantName)).get_item("authorization_endpoint")
    
    #Can't sideload the DLL for this one since the AppCert isn't pass correclty.
    $tMod = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
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
            Write-Error "No Access Token"
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
