# Invoke-WMILM
This is a PoC script for various methods to acheive authenticated remote code execution via WMI, without (at least directly) using the Win32_Process class. The type of technique is determined by the "Type" parameter. 

## Parameters
* Target - Name or IP of target machine
* Type - The type of technique to use
* Name - For techniques creating named objects (services, tasks etc.)
* Command - Executable to run
* CommandArgs - Arguments to the executable
* CleanUp - an optional phase to remove artifacts created by the various techniques
* Username
* Password


## Supported Techniques
* DerivedProcess - Creates a class deriving from Win32_Process, and calls the Create method of that class
* Service - Creates a service and runs it using WMI. Basically PSEXEC with different network traffic.
* Job - Creates an at.exe style scheduled task to run in 30 seconds
* Task - Creates an schtasks.exe style scheduled task and runs it
* Product - Runs an arbitrary MSI file from a given path (given by the Command parameter)
* Provider - Creates a new provider with the command and arguments as the underlying COM object, and loads it
