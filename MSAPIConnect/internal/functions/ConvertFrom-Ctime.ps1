<#
.SYNOPSIS
Convert Date Time to Unix Time

.DESCRIPTION
Convert Date Time to Unix Time

.PARAMETER ctime
Date and Time to convert to UNIX time

.EXAMPLE
Convert Time to Unix Time
ConvertFrom-Ctime -ctime "2019-02-27 1:00:00"

.NOTES
From : https://stackoverflow.com/questions/4192971/in-powershell-how-do-i-convert-datetime-to-unix-time/
#>

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
