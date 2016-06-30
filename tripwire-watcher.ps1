## RUN with powershell as a task on start with these options: -NoExit -NoLogo -File C:\path-to-script\tripwire-watcher.ps1
## SETTINGS
$mailtos = @("recepient1@example.com", "recepient2@example.com", "recepient3@example.com")
$smtpFrom = "fileserver@example.com"
$smtpServer = "mail.example.com"
#The sample file to compare the trigger files to.
$sample = "C:\CryptoLocker-Watcher\sample\loremipsum.docx"
#Trigger files
$triggerfilesArr = @("D:\File Server\1\___aaa-NODELETE\___aaa-NODELETE.docx", "F:\File Server\1\aaa-NODELETE\aaa-NODELETE.docx", "F:\File Server\1\zzz-NODELETE\zzz-NODELETE.docx", "F:\File Server\1\zzz-NODELETE.docx")

### SENDMAIL
function sendMail($s){
    $messageSubject = $s[0]
    $message = New-Object System.Net.Mail.MailMessage
    $message.From = $smtpfrom
    foreach($mailto in $mailtos){$message.To.Add($mailto)}
    $message.Subject = $messageSubject
    $message.IsBodyHTML = $false
    $message.Body = $s[1]
    $smtp = New-Object Net.Mail.SmtpClient($smtpServer)
    $smtp.Send($message)
}

### UNREGISTER ALL REGISTERED EVENTS AT ONCE
function unregisterAllEvents(){
    foreach($i in $triggerfilesArr){
        $path = Split-Path $i
        Unregister-Event "$path+folderDeleted"
        Unregister-Event "$path+folderChanged"
        Unregister-Event "$path+folderRenamed"
        Unregister-Event "$path+folderCreated"
    }
}

### COMPARE MD5 HASH WITH THE TRIGGER FILE
function compareHash($compareWith){
    try{#TRIGGER FILE FOUND. CHECK HASH
        if (!($sampleHash.Equals((Get-FileHash -Path $compareWith -Algorithm MD5 | Format-Wide -Property Hash | Out-String)))){
            return 1
        }
       }
    catch{#TRIGGER FILE NOT FOUND
        return 2
    }
    return 0
}

### DEFINE ACTION HERE (STOP SERVICE, SHUTDOW HOST)
function takeAction(){
    unregisterAllEvents
#    Stop-Service -Force -InputObject(Get-Service -ComputerName as -Name "YOURSERVICE").Stop()
}

### START MAIN
# FIND CONFIGURED TRIGGER FILE BEFORE ENABLING WATCHERS
try{$sampleHash = Get-FileHash -Path $sample -Algorithm MD5 | Format-Wide -Property Hash | Out-String}
catch{
    $subject = "The trigger file $sample is missing"
    $body = "The trigger file $sample on $env:computername was not found or access was denied to $env:username. The script execution has been stopped."
    $email =@($subject,$body)
    sendMail -s $email
    Exit
}

## COMPARE CONFIGURED FILE HASHES BEFORE ENABLING WATCHERS
foreach($i in $triggerfilesArr){
    if ((compareHash $i)-gt 0){
            $subject = "The trigger and sample files do not match"
            $body = "The trigger file $i does not match the sample file $sample on $env:computername. The script execution has been stopped."
            $email =@($subject,$body)
            sendMail -s $email
            Exit
    }
}

#CREATE ONE FileSystemWatcher OBJECT FOR EVERY TRIGGER FILE
foreach($i in $triggerfilesArr){
    $path = Split-Path $i
    $file = Split-Path $i -leaf
    $Watcher = New-Object IO.FileSystemWatcher $path, $file -Property @{IncludeSubdirectories = $false;NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'}
### DELETED Event
    Register-ObjectEvent $Watcher Deleted -SourceIdentifier "$path+folderDeleted" -Action{
        $name = $Event.SourceEventArgs.Name
        $changeType = $Event.SourceEventArgs.ChangeType
        $timeStamp = $Event.TimeGenerated
        if ((compareHash $name)-gt 0){
            $subject = "CRYPTOLOCKER ALERT: The trigger file has been deleted"
            $body = "The trigger file $name has been deleted from $env:computername at $timeStamp ($env:username). The script execution has been stopped."
            $email =@($subject,$body)
            sendMail -s $email
            takeAction
            Write-Host "The file '$name' was $changeType at $timeStamp" -fore red
            Exit
        }
        $subject = "CRYPTOLOCKER ALERT: The trigger file has been deleted"
        $body = "The trigger file $name has been deleted from $env:computername at $timeStamp ($env:username). The script execution has been stopped."
        $email =@($subject,$body)
        sendMail -s $email
        takeAction
        Write-Host "The file '$name' was $changeType at $timeStamp" -fore red
        Exit
    }#DELETED ACTION END

### Changed Event
    Register-ObjectEvent $Watcher changed -SourceIdentifier "$path+folderChanged" -Action{
        $name = $Event.SourceEventArgs.Name
        $changeType = $Event.SourceEventArgs.ChangeType
        $timeStamp = $Event.TimeGenerated
        if ((compareHash $name)-gt 0){
            $subject = "CRYPTOLOCKER ALERT: The trigger file has been changed"
            $body = "The trigger file $name has been changed on $env:computername at $timeStamp ($env:username). The script execution has been stopped."
            $email =@($subject,$body)
            sendMail -s $email
            takeAction
            Write-Host "The file '$name' was $changeType at $timeStamp" -fore red
            Exit
        }
        $subject = "CRYPTOLOCKER ALERT: The trigger file has been changed"
        $body = "The trigger file $name has been reported as changed on $env:computername at $timeStamp ($env:username). The script execution has been stopped."
        $email =@($subject,$body)
        sendMail -s $email
        takeAction
        Write-Host "The file '$name' was $changeType at $timeStamp" -fore red
        Exit
    }#CHANGED ACTION END

### Renamed Event
    Register-ObjectEvent $Watcher Renamed -SourceIdentifier "$path+folderRenamed" -Action {
        $name = $Event.SourceEventArgs.Name
        $changeType = $Event.SourceEventArgs.ChangeType
        $timeStamp = $Event.TimeGenerated
        if ((compareHash $name)-gt 0){
            $subject = "CRYPTOLOCKER ALERT: The trigger file has been moved"
            $body = "The trigger file $name has been moved on $env:computername at $timeStamp ($env:username). The script execution has been stopped."
            $email =@($subject,$body)
            sendMail -s $email
            takeAction
            Write-Host "The file '$name' was $changeType at $timeStamp" -fore red            
            Exit
        }
        $subject = "CRYPTOLOCKER ALERT: The trigger file has been moved"
        $body = "The trigger file $name has been reported as moved on $env:computername at $timeStamp ($env:username). The script execution has been stopped."
        $email =@($subject,$body)
        sendMail -s $email
        takeAction
        Write-Host "The file '$name' was $changeType at $timeStamp" -fore red
        Exit
    }#Renamed ACTION END

### Created Event
    Register-ObjectEvent $Watcher Created -SourceIdentifier "$path+folderCreated" -Action {
        $name = $Event.SourceEventArgs.Name
        $changeType = $Event.SourceEventArgs.ChangeType
        $timeStamp = $Event.TimeGenerated
        if ((compareHash $name)-gt 0){
            $subject = "CRYPTOLOCKER ALERT: The trigger file has been moved"
            $body = "The trigger file $name has been moved on $env:computername at $timeStamp ($env:username). The script execution has been stopped."
            $email =@($subject,$body)
            sendMail -s $email
            takeAction
            Write-Host "The file '$name' was $changeType at $timeStamp" -fore red
            Exit
        }
        $subject = "CRYPTOLOCKER ALERT: The trigger file has been moved"
        $body = "The trigger file $name has been reported as moved on $env:computername at $timeStamp ($env:username). The script execution has been stopped."
        $email =@($subject,$body)
        sendMail -s $email
        takeAction
        Write-Host "The file '$name' was $changeType at $timeStamp" -fore red
        Exit
    }#Created ACTION END
}#FOREACH END
