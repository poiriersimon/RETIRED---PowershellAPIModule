Function Get-CurrentUPN
{
	[CmdletBinding()]
	param (

	)
	$UserPrincipalName = ([ADSI] "LDAP://<SID=$(([System.Security.Principal.WindowsIdentity]::GetCurrent()).User)>").userPrincipalName
	Return $UserPrincipalName
}
