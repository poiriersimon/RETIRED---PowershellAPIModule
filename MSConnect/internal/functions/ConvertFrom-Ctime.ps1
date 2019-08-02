#From : https://stackoverflow.com/questions/4192971/in-powershell-how-do-i-convert-datetime-to-unix-time/
function ConvertFrom-Ctime
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
