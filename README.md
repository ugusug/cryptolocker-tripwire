# cryptolocker-tripwire
PS script for file monitoring

SYNOPSIS

This PowerShell script is made to watch, take action and/or report manipulations of specified files in specified locations on a file server. It is made to deter cryptolocker from changing data contents of a number of specified "tripwire" files, moving or renaming them. It might prove useful to choose the tripwire file names so they appear at the top and the bottom of the file system (like "__aaa..." and "zzz...") if cryptolocker starts the encryption in alphabetical order the tripwire files would become the first to be encrypted and hence changed thus triggering the script response. The trigger files should get names which will tell the file server users to not open, move or delete them. Also one tripwire file can be placed in every fixed (assuming there are any) folder on the file server.

COMPATIBILTY

PowerShell 4.0 or 5.0 is required to run the script. Use "Get-Host" on your target machine to see your PS version.

INSTALLATION AND USE

1. Copy the tripwire script to a folder with the administrative access only. E.g. create a folder named C:\tripwire and copy it there.
2. Create ONE sample file to check against and place it in that same administrative folder. 
3. Create tripwire folders and copy the tripwire files under desired names into them. Or just copy the sample file into the designated folders and rename it accordingly. So far only one file per folder will work, but I plan to change it in the next version. 
4. Change the variables (mail alert recipient, SMTP server and the tripwire files) in the script. You can define your preferred action in the "takeAction" function like stopping the "lanmanserver" service.
5. Create a new task with highest privileges in the task scheduler. The action should be "powershell" with the following arguments:
"-NoExit -NoLogo -File C:\path-to-script\tripwire-server.ps1"
The task will show that the script exited, but it keeps watching the folders with a very small resource footprint.

TODO

1. Multiple tripwire files per folder
2. SMTP authentication
