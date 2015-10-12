# Script name:   	naf_perfmon_to_influxdb.ps1
# Version:			v0.07.151012
# Created on:    	01/02/2014																			
# Author:        	D'Haese Willem
# Purpose:       	Initiate WSUS Update installation
# Recent History:       	
#	24/09/15 => Extra debugging options, improved method
#	09/10/15 => Cleanup and prep for curl
#	10/11/15 => Integrated curl
#	11/10/15 => Finalized bulk upload through curl and moved metrics to struct
#	12/10/15 => Cleanup and consolidated fuctions
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#	by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#	in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#	PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#	License along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Requires –Version 4.0

$InfluxStruct = New-Object PSObject -Property @{
	StopWatch = [System.Diagnostics.Stopwatch]::StartNew();
	LoopStopWatch = '';
	LoopNumber = 0;
    Hostname = ([System.Net.Dns]::GetHostByName((hostname.exe)).HostName).tolower();
    ExitCode = [int]3;
    OutputString = [string]'Unknown: Error processing, no data returned.';
    LogLocal = 'C:\Nagios\NAF\NAF_Logs\NAF_Influx.log';
    ConfigPath = 'C:\Program Files\NSClient++\scripts\powershell\config\naf_windows_perfmon_to_influxdb.xml';
    CurlPath = 'C:\Nagios\NAF\NAF_Sources\Tools\curl\curl.exe';
    InfluxDbServer = '';
    InfluxDbPort = 8086;
    InfluxDbName = '';
    InfluxDbUser = '';
    InfluxDbPassword = '';
    MetricsHash = @{};
    MetricsString = '';
    MaxSamples = 25;
    Interval = 5
}

$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

#region Functions
function Test-FileLock {
      param ([parameter(Mandatory=$true)][string]$Path)
  $oFile = New-Object System.IO.FileInfo $Path
  try
  {
      $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
      if ($oStream)
      {
        $oStream.Close()
      }
      return $false
  }
  catch
  {
    return $true
  }
}
function Write-Log {
    param (
	[parameter(Mandatory=$true)][string]$Log,
	[parameter(Mandatory=$true)][string]$Severity,
	[parameter(Mandatory=$true)][string]$Message
	)
	$Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
    if ($Log -eq 'Verbose') {
    	Write-Verbose "${Now}: ${Severity}: $Message"
    }
	elseif ($Log -eq 'Debug') {
    	Write-Debug "${Now}: ${Severity}: $Message"
    }
	elseif ($Log -eq 'Output') {
    	Write-Host "${Now}: ${Severity}: $Message"
    }
    else {
		if (!(Test-Path -Path $Log)){
			try {
				New-Item -Path $Log -Type file -Force | Out-null	
			}
			catch {
				$Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
				Write-Host "${Now}: Error: Write-Log was unable to find or create the path `"$Log`". Please debug.."
				exit 1
			}
		}
        $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
	    while (Test-FileLock $Log) {Start-Sleep (Get-Random -minimum 1 -maximum 10)}
	    "${Now}: ${Severity}: $Message" | Out-File -filepath $Log -Append
	}
}

function Get-PrettyProblem {
    param (
        $Problem
    )
	$InfluxStruct.StopWatch.Stop()
    $prettyString = (Out-String -InputObject (format-list -inputobject $Problem -Property * -force)).Trim() + "`nCurrent loop $($InfluxStruct.LoopNumber) stopped after $($InfluxStruct.LoopStopWatch.Elapsed.TotalSeconds) seconds.`nScript stopped after $($InfluxStruct.StopWatch.Elapsed.TotalSeconds) seconds."
    return $prettyString
}

Function Initialize-Args {
    Param ( 
        [Parameter(Mandatory=$True)]$Args
    )
	
    try {
        For ( $i = 0; $i -lt $Args.count; $i++ ) { 
		    $CurrentArg = $Args[$i].ToString()
            if ($i -lt $Args.Count-1) {
				$Value = $Args[$i+1];
				If ($Value.Count -ge 2) {
					foreach ($Item in $Value) {
						Test-Strings $Item | Out-Null
					}
				}
				else {
	                $Value = $Args[$i+1];
					Test-Strings $Value | Out-Null
				}	                             
            } else {
                $Value = ''
            };

            switch -regex -casesensitive ($CurrentArg) {
                "^(-H|--Hostname)$" {
                    if ($value -match "^[a-zA-Z0-9._-]+$") {
                        $InfluxStruct.Hostname = $value
                    } else {
                        throw "Hostname does not meet regex requirements (`"^[a-zA-Z0-9._-]+$`"). Value given is `"$value`"."
                    }
                    $i++
                }
                "^(-S|--InfluxDbServer)$" {
                    if ($value -match "^[a-zA-Z0-9._-]+$") {
                        $InfluxStruct.InfluxDbServer = $value
                    } else {
                        throw "InfluxDbServer does not meet regex requirements (`"^[a-zA-Z0-9._-]+$`"). Value given is `"$value`"."
                    }
                    $i++
                }
                "^(-p|--InfluxDbPort)$" {
                    if ($value -match "^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$") {
                        $InfluxStruct.InfluxDbPort = $value
                    } else {
                        throw "InfluxDbPort does not meet regex requirements (`"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`"). Value given is `"$value`"."
                    }
                    $i++
                 }
                "^(-db|--Database)$" {
                    if ($value -match "^[a-zA-Z0-9._-]+$") {
                        $InfluxStruct.InfluxDbName = $value
                    } else {
                        throw "InfluxDbName does not meet regex requirements (`"^[a-zA-Z0-9._-]+$`"). Value given is `"$value`"."
                    }
                    $i++
                }
                "^(-u|--User)$" {
                    if ($value -match "^[a-zA-Z0-9._-]+$") {
                        $InfluxStruct.InfluxDbUser = $value
                    } else {
                        throw "InfluxDbUser does not meet regex requirements (`"^[a-zA-Z0-9._-]+$`"). Value given is `"$value`"."
                    }
                    $i++
                }
                "^(-pw|--Password)$" {
                    if ($value -match "^[a-zA-Z0-9._-]+$") {
                        $InfluxStruct.InfluxDbPassword = $value
                    } else {
                        throw "InfluxDbPassword does not meet regex requirements (`"^[a-zA-Z0-9._-]+$`"). Value given is `"$value`"."
                    }
                    $i++
                }
                "^(-ms|--MaxSamples)$" {
                    if (($value -match "^[\d]+$") -and ([int]$value -lt 100000)) {
                        $InfluxStruct.MaxSamples = $value
                    } else {
                        throw "MaxSamples does not meet regex requirements (`"^[\d]+$`"). Value given is `"$value`"."
                    }
                    $i++
                 }
                "^(-I|--Interval)$" {
                    if (($value -match "^[\d]+$") -and ([int]$value -lt 7200)) {
                        $InfluxStruct.Interval = $value
                    } else {
                        throw "Interval does not meet regex requirements (`"^[\d]+$`"). Value given is `"$value`"."
                    }
                    $i++
                 }
                "^(-h|--Help)$" {
                    Write-Help
                }
                default {
                    throw "Illegal arguments detected: $_"
                 }
            }
        }
    } 
    catch {
		Write-Host "Error: $_"
        Exit 2
	}	
}

Function Test-Strings {
    Param ( [Parameter(Mandatory=$True)][string]$String )
    $BadChars=@("``", '|', ';', "`n")
    $BadChars | ForEach-Object {
        If ( $String.Contains("$_") ) {
            Write-Host "Error: String `"$String`" contains illegal characters."
            Exit $DiskStruct.ExitCode
        }
    }
    Return $true
} 

Function Write-Help {
	Write-Host @"
naf_windows_perfmon_to_influxdb.ps1:
This script is designed to start writing perfmon data to InfluxDB.
Arguments:
    -H 	 | --Hostname			=> Optional hostname of remote system, default is localhost, not yet tested on remote host.
    -S	 | --InfluxDbServer		=> InfluxDb server which will store the data.
    -p	 | --InfluxDbPort		=> InfluxDb server port.
    -db	 | --Database			=> InfluxDb database.
    -u	 | --User				=> InfluxDb user.
    -p   | --Password			=> InfluxDb password.
    -ms  | --MaxSamples			=> Maximum Samples to gather.
    -I   | --Interval			=> Interval to gather and send samples.
    -h   | --Help 				=> Print this help output.
"@
    Exit $FluxStruct.ExitCode;
}
 
Function Import-XMLConfig
{
    [hashtable]$Config = @{ }
    $xmlfile = [xml]([System.IO.File]::ReadAllText($InfluxStruct.ConfigPath))
    $Config.MetricTimeSpan = [timespan]::FromSeconds($InfluxStruct.Interval)
    $Config.Counters = @()
    foreach ($counter in $xmlfile.Configuration.PerformanceCounters.Counter) {
        $Config.Counters += $counter.Name
    }
    $Config.MetricReplace = New-Object System.Collections.Specialized.OrderedDictionary
    ForEach ($metricreplace in $xmlfile.Configuration.MetricCleaning.MetricReplace) {
        $Config.MetricReplace.Add($metricreplace.This,$metricreplace.With)
    }
    $Config.Filters = [string]::Empty;
    foreach ($MetricFilter in $xmlfile.Configuration.Filtering.MetricFilter) {
        $Config.Filters += $MetricFilter.Name + '|'
    }
    if($Config.Filters.Length -gt 0) {
        $Config.Filters = $Config.Filters.Trim()
        $Config.Filters = $Config.Filters.TrimEnd('|')
    }
    else {
        $Config.Filters = $null
    }
    Return $Config
}

function Send-Metrics {
    $InfluxStruct.MetricsString = ''
    foreach ($key in $InfluxStruct.MetricsHash.Keys) {  
        $InfluxStruct.MetricsString += "$key,host=$($InfluxStruct.Hostname),region=test value=$($InfluxStruct.MetricsHash[$key])"
        Write-Log Debug Info "Metrics Received. Key: $key, Value: $($InfluxStruct.MetricsHash[$key])"
        $InfluxStruct.MetricsString += "`n"
    }
   	Write-Log Debug Info "MetricsString: $($InfluxStruct.MetricsString)"
    Write-Log verbose Info "Attempting to send Metrics to Server $($InfluxStruct.InfluxDbServer) on port $($InfluxStruct.InfluxDbPort)."
	$CurlCommand = "$($InfluxStruct.CurlPath) -u $($InfluxStruct.InfluxDbUser):$($InfluxStruct.InfluxDbPassword) -i -XPOST `"http://$($InfluxStruct.InfluxDbServer):$($InfluxStruct.InfluxDbPort)/write?db=$($InfluxStruct.InfluxDbName)`" --data-binary `'$($InfluxStruct.MetricsString)`'"
	Write-Log Debug Info "Command: $CurlCommand"
	try {
		$Res = Invoke-Expression $CurlCommand 2>&1
	}	
	catch {
		Write-Log Output Error "Something went wrong while sending metrics. Expression result: $Res"
	}	
	Write-Log Verbose Info "Sent metrics successfuly. Result: `n$Res"
}

Function ConvertTo-InfluxDBMetric
{
    param (
        [CmdletBinding()]
        [parameter(Mandatory = $true)][string]$MetricToClean,
        [parameter(Mandatory = $false)][switch]$RemoveUnderscores,
        [parameter(Mandatory = $false)][switch]$NicePhysicalDisks,
        [parameter(Mandatory = $false)][System.Collections.Specialized.OrderedDictionary]$MetricReplacementHash
    )

    if ($MetricReplacementHash -ne $null)
    {
        $cleanNameOfSample = $MetricToClean   
        ForEach ($m in $MetricReplacementHash.GetEnumerator())
        {
            If ($m.Value -cmatch '#{CAPTUREGROUP}') {
                $cleanNameOfSample -match $m.Name | Out-Null
                $replacementString = $m.Value -replace '#{CAPTUREGROUP}', $Matches[1]
                $cleanNameOfSample = $cleanNameOfSample -replace $m.Name, $replacementString
            }
            else {
                Write-Log Debug Info  "Replacing: $($m.Name) With : $($m.Value)"
                $cleanNameOfSample = $cleanNameOfSample -replace $m.Name, $m.Value
            }
        }
    }
    else {
        $cleanNameOfSample = $MetricToClean -replace '^\\\\', ''
        $cleanNameOfSample = $cleanNameOfSample -replace '\\\\', '.'
        $cleanNameOfSample = $cleanNameOfSample -replace ':', '.'
        $cleanNameOfSample = $cleanNameOfSample -replace '\/', '-'
        $cleanNameOfSample = $cleanNameOfSample -replace '\\', '.'
        $cleanNameOfSample = $cleanNameOfSample -replace '\(', '.'
        $cleanNameOfSample = $cleanNameOfSample -replace '\)', ''
        $cleanNameOfSample = $cleanNameOfSample -replace '\]', ''
        $cleanNameOfSample = $cleanNameOfSample -replace '\[', ''
        $cleanNameOfSample = $cleanNameOfSample -replace '\%', ''
        $cleanNameOfSample = $cleanNameOfSample -replace '\s+', ''
        $cleanNameOfSample = $cleanNameOfSample -replace '\.\.', '.'
    }

    if ($RemoveUnderscores) {
        Write-Log Verbose Info 'Removing Underscores as the switch is enabled.'
        $cleanNameOfSample = $cleanNameOfSample -replace '_', ''
    }

    if ($NicePhysicalDisks) {
        $driveLetter = ([regex]'physicaldisk\.\d([a-zA-Z])').match($cleanNameOfSample).groups[1].value
        $cleanNameOfSample = $cleanNameOfSample -replace 'physicaldisk\.\d([a-zA-Z])', ('physicaldisk.' + $driveLetter + '-drive')
        $niceDriveLetter = ([regex]'physicaldisk\.(.*)\.avg\.').match($cleanNameOfSample).groups[1].value
        $cleanNameOfSample = $cleanNameOfSample -replace 'physicaldisk\.(.*)\.avg\.', ('physicaldisk.' + $niceDriveLetter + '.')
    }
    Write-Log Debug Info "Counter $MetricToClean converted to $cleanNameOfSample."
    Write-Output $cleanNameOfSample
}

Function Start-StatsToInfluxDB
{
	Write-Log Verbose Info "Attempting to import configuration file `"$InfluxStruct.configPath`"."
	try {
    	$Config = Import-XMLConfig
	}
	catch {
		Write-Log Verbose Error "Import configuration file `"$InfluxStruct.configPath`" failed. Please check if the file exists and is readable."
		$exceptionText = Get-PrettyProblem $_
        Write-Error "Import configuration file failed. Error: `n$exceptionText"
		exit 1
	}
	$configFileLastWrite = (Get-Item -Path $InfluxStruct.configPath).LastWriteTime
	Write-Log Verbose Info "Import configuration file `"$InfluxStruct.configPath`" succeeded. Last write time is $configFileLastWrite. Continuing..."	
    $sleep = 0
    while ($true) {
		$InfluxStruct.LoopNumber++
		$InfluxStruct.LoopStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        if($sleep -gt 0) {
            Start-Sleep -Milliseconds $sleep
        }
        $iterationStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $nowUtc = [datetime]::UtcNow
        $nowUtc = $nowUtc.AddSeconds(- ($nowUtc.Second % $InfluxStruct.Interval))
        $InfluxStruct.MetricsHash = @{}
        $metricsToSend = @{}
		Write-Log Verbose Info 'Attempting to collect counter samples.'
        try {
			$collections = Get-Counter -Counter $Config.Counters -SampleInterval 1 -MaxSamples 1
        	$samples = $collections.CounterSamples
		}
		catch {
			Write-Log Verbose Error 'Collecting counter samples failed.'
			$exceptionText = Get-PrettyProblem $_
	        Write-Error "Collecting counter samples failed. Error: `n$exceptionText"
			exit 1
		}		
        Write-Log Verbose Info 'All counter Samples Collected successfully.'
        foreach ($sample in $samples) {
            $filterStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            Write-Log Debug Info "Sample Name to clean: $($sample.Path)"
            if ([string]::IsNullOrWhiteSpace($Config.Filters) -or $sample.Path -notmatch [regex]$Config.Filters) {
                $cleanNameOfSample = ConvertTo-InfluxDBMetric -MetricToClean $sample.Path -MetricReplacementHash $Config.MetricReplace
                $metricPath = $cleanNameOfSample -replace '^[a-z0-9]*.', ''
                Write-Log Debug Info "Converted $cleanNameOfSample to $metricPath"
                $InfluxStruct.MetricsHash[$metricPath] = $sample.Cookedvalue
                $metricsToSend[$metricPath] = $sample.Cookedvalue
            }
             else {
                Write-Log Debug Info "Filtering out Sample Name: $($sample.Path) as it matches something in the filters."
            }
            $filterStopWatch.Stop()
			Write-Log Debug Info "Cleaning metric took $($filterStopWatch.Elapsed.TotalSeconds) seconds."    
        }

        Send-Metrics

        if((Get-Item $InfluxStruct.configPath).LastWriteTime -gt (Get-Date -Date $configFileLastWrite)) {
            $Config = Import-XMLConfig
        }
        $iterationStopWatch.Stop()
        $collectionTime = $iterationStopWatch.Elapsed
        if ($InfluxSTruct.MaxSamples -le $InfluxStruct.LoopNumber) {
        	Write-Log Verbose Info "PerfMon Job Number $($InfluxStruct.LoopNumber) Execution Time: $($collectionTime.TotalSeconds) seconds."
            Write-Log Verbose Info "MaxSamples of $($InfluxSTruct.MaxSamples) reached. Exiting"
            exit 0
        }
        $sleep = $Config.MetricTimeSpan.TotalMilliseconds - $collectionTime.TotalMilliseconds
        Write-Log Verbose Info "PerfMon Job Number $($InfluxStruct.LoopNumber) Execution Time: $($collectionTime.TotalSeconds) seconds. Next sleep: $sleep."
    }
}

#endregion 

# Main function 

Write-Log Verbose Info 'Influx structure created successfully. Initializing arguments.'

if ($Args) {
    if($Args[0].ToString() -ne "$ARG1$") {
	    if($Args.count -ge 1){Initialize-Args $Args}
    }
	else {
		Write-Log Verbose Info 'No arguments passed, except $ARG1$. Attempting to use default values defined in InfluxStruct.'
	}
}
else {
	Write-Log Verbose Info 'No arguments detected. Attempting to use default values defined in InfluxStruct.'
}

Write-Log Verbose Info 'Starting primary function `"Start-StatsToInfluxDB`".'
Start-StatsToInfluxDB
Write-Log Verbose Info "Primary function `"Start-StatsToInfluxDB`" exited, what`'s strange considering it shouldn`'t"