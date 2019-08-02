function ConvertFromCtime
{
	[CmdletBinding()]
	param (
		[Int]
		$ctime
	)
    [datetime]$epoch = '1970-01-01 00:00:00'    
    [datetime]$result = $epoch.AddSeconds($Ctime)
    return $result
}
