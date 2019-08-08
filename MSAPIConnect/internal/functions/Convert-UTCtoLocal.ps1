﻿<#
.SYNOPSIS
Convert UTC Time to Local Time

.DESCRIPTION
Convert UTC Time to Local Time

.PARAMETER UTCTime
UTC DATE Time Value

.EXAMPLE
Convert-UTCtoLocal -UTCTime "2019-02-27 1:00:00"

.NOTES
From : https://devblogs.microsoft.com/scripting/powertip-convert-from-utc-to-my-local-time-zone/
#>

function Convert-UTCtoLocal
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [String] $UTCTime
    )

    $strCurrentTimeZone = (Get-TimeZone).StandardName
    $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
    $LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
    Return $LocalTime
}
