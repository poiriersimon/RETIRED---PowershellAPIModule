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
        Write-Error "Couldn't complete"
    }
    Return $UsageData
}
