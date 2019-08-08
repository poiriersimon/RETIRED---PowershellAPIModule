<#
.SYNOPSIS
Send Query to the Microsofrt Reports API

.DESCRIPTION
Send Query to the Microsofrt Reports API with Azure AD Application

.PARAMETER ClientID
This is the Client ID (Application ID) of the registered Azure AD Application.
The Application need to have the right permission in your tenant.
#TODO = Document the minimal app permission

.PARAMETER ClientSecret
If you are leveraging an Azure AD Application with Client Secret authentication, you need to provide the Secret here

.PARAMETER TenantName
For Azure AD Application Authentication, you need to specify the Tenant Name, Tenant ID or Registered Domain name on your Azure or Office 365 Tenant

.PARAMETER Query
Optional, Additionnal Graph URL to pass to https://graph.microsoft.com/V1.0/reports like "getEmailActivityUser", if no value getEmailActivityUserDetail are used
Currently, there no validation, so refer to the docs.microsoft.com API 
#TODO - add url for docs

.EXAMPLE
Get-GraphUsageReportData -ClientID $ClientID -ClientSecret $ClientSecret -TenantName contoso.com -Query "getEmailActivityUserDetail(period='D180')"

.NOTES
Based on https://www.altitude365.com/2018/09/23/retrieve-and-analyze-office-365-usage-data-with-powershell-and-microsoft-graph-api/
#TODO - Add Client Cert Auth
#TODO - Add API Version
#>

function Get-GraphUsageReportData {
    [CmdletBinding()]
    param (
    [parameter(Mandatory = $true)]
    [string]$ClientID,

   [parameter(Mandatory = $true)]
    [string]$ClientSecret,

   [parameter(Mandatory = $true)]
    [string]$TenantName,

    [parameter(Mandatory=$false)]
    $Query = "getEmailActivityUserDetail(period='D180')"
    )
   try {
    # Call Microsoft Graph and extract CSV content and convert data to PowerShell objects.
        $UsageData = (Invoke-GraphApi -TenantName $TenantName -Resource reports -QueryParams $Query -ClientID $ClientID -ClientSecret $ClientSecret)| ConvertFrom-Csv
    }
    catch {
        Throw "Couldn't complete"
    }
    Return $UsageData
}
