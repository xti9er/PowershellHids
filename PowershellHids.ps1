#by xti9er	www.xtiger.net  https://github.com/xti9er/PowershellHids 
# powershell HIDS DEMO 2015.11.18

$Query = 'SELECT * FROM Win32_ProcessStartTrace'            
$action = { 
	
  try{
    $e = $Event.SourceEventArgs.NewEvent  

    $pproc= Get-WmiObject win32_process|where{$_.ProcessID -eq $e.ParentProcessId}
    $ppid=$e.ParentProcessId
    $puser= $pproc.getowner().User 
    $pname= $pproc.ProcessName 
    $pcmd=  $pproc.CommandLine
    $ppath= $pproc.Path

    $cproc= Get-WmiObject win32_process|where{$_.ProcessID -eq $e.ProcessId}
    $cuser= $cproc.getowner().User 
    $csid=$e.SessionId
    $cpid=$e.ProcessId
    $cname= $e.ProcessName
    $ccmd= $e.CommandLine
    $cpath=$e.Path

    $fmt = '[*] sid={0,2} ,ID={1,5}, Parent={2,5}, Time={3,20}, Name="{4}" user="{5}" puser="{6}"'            
    $msg = $fmt -f $csid, $cpid, $ppid,$event.TimeGenerated, $cname,$cuser,$puser
    $alert="[!] Provilege Escalation `n[$ppid|$puser]",$pname,$pcmd,$ppath,"`n`t|___[$cpid|$cuser]",$cname,$ccmd,$cpath
    if(($puser -ne $cuser) -and ($puser -ne "system")){
    	Write-host -ForegroundColor Red $alert 
	Write-EventLog -logname application -source "powershell-hids" -EntryType warning -EventId 1 -Message "$alert"
    }
    else{
    	Write-host -ForegroundColor yellow $msg     
    }   
  }
  catch {

    Write-Host "General exception: $($_.Exception.Message)"

  }  
  Remove-Variable $e
}            
Register-WmiEvent -Query $Query -SourceIdentifier ProcessStart -Action $Action

