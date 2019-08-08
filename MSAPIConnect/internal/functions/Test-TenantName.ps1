<#
.SYNOPSIS
Validate than the tenant name is a domain, else add .onmicrosoft.com

.DESCRIPTION
Validate than the tenant name is a domain, else add .onmicrosoft.com

.PARAMETER TenantName
Value to validate

.EXAMPLE
Validate if the tenant name is correct or add .onmicrosoft.com if it isn't a domain
Test-TenantName -TenantName Contoso

.NOTES
#
#>

Function Test-TenantName
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [System.String]
        $TenantName
    )
    if($TenantName -notlike "*.onmicrosoft.com"){
        $TenantName = $TenantName + ".onmicrosoft.com"
    }
    Return $TenantName
}
