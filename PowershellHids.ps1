#by xti9er	www.xtiger.net  https://github.com/xti9er/PowershellHids 
# powershell HIDS DEMO 2015.11.18

if(-not (Get-EventLog -logname application -source "powerhsell-HIDS" -Newest 1)){
	New-EventLog -logname application -source "powerhsell-HIDS" 
}
$Query = 'SELECT * FROM Win32_ProcessStartTrace'            
$action = { 
    $e = $Event.SourceEventArgs.NewEvent  
    $user=  (Get-WmiObject win32_process|where{$_.ProcessID -eq $e.ProcessId}).getowner().User  
    $puser=  (Get-WmiObject win32_process|where{$_.ProcessID -eq $e.ParentProcessId}).getowner().User 
    $pname=  (Get-WmiObject win32_process|where{$_.ProcessID -eq $e.ParentProcessId}).ProcessName 
    $pcmd=  (Get-WmiObject win32_process|where{$_.ProcessID -eq $e.ParentProcessId}).CommandLine
    $ppath=  (Get-WmiObject win32_process|where{$_.ProcessID -eq $e.ParentProcessId}).Path

    $fmt = 'ProcessStarted: (sid={0,2} ,ID={1,5}, Parent={2,5}, Time={3,20}, Name="{4}" user="{5}" puser="{6}")'            
    $msg = $fmt -f $e.SessionID, $e.ProcessId, $e.ParentProcessId, $event.TimeGenerated, $e.ProcessName,$user,$puser
    $alert="[!] Provilege Escalation `n[",$e.ParentProcessId,"]",$pname,$pcmd,$ppath,"`n`t|___[",$e.ProcessId,"]",$e.ProcessName,$e.CommandLine,$e.Path
    if(($puser -ne $user) -and ($puser -ne "system")){
    	Write-host -ForegroundColor Red $alert 
	Write-EventLog -logname application -source "powershell-HIDS" -EntryType warning -EventId 1 -Message $alert
    }
    
    Write-host -ForegroundColor blue $msg            
     
}            
Register-WmiEvent -Query $Query -SourceIdentifier ProcessStart -Action $Action

