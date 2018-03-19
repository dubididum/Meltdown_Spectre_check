#checks status of CVE-2017-5715 (Spectre) & CVE-2017-5754 (Meltdown)
$errorvar = $null

function Remove-WriteHost
{
   [CmdletBinding(DefaultParameterSetName = 'FromPipeline')]
   param(
     [Parameter(ValueFromPipeline = $true, ParameterSetName = 'FromPipeline')]
     [object] $InputObject,

     [Parameter(Mandatory = $true, ParameterSetName = 'FromScriptblock', Position = 0)]
     [ScriptBlock] $ScriptBlock
   )

   begin
   {
     function Cleanup
     {
       # clear out our proxy version of write-host
       remove-item function:\write-host -ea 0
     }

     function ReplaceWriteHost([string] $Scope)
     {
         Invoke-Expression "function ${scope}:Write-Host { }"
     }

     Cleanup

     # if we are running at the end of a pipeline, need to immediately inject our version
     #    into global scope, so that everybody else in the pipeline uses it.
     #    This works great, but dangerous if we don't clean up properly.
     if($pscmdlet.ParameterSetName -eq 'FromPipeline')
     {
        ReplaceWriteHost -Scope 'global'
     }
   }

   process
   {
      # if a scriptblock was passed to us, then we can declare
      #   our version as local scope and let the runtime take it out
      #   of scope for us.  Much safer, but it won't work in the pipeline scenario.
      #   The scriptblock will inherit our version automatically as it's in a child scope.
      if($pscmdlet.ParameterSetName -eq 'FromScriptBlock')
      {
        . ReplaceWriteHost -Scope 'local'
        & $scriptblock
      }
      else
      {
         # in pipeline scenario, just pass input along
         $InputObject
      }
   }

   end
   {
      Cleanup
   }  
}


#force execution policy to remotesigned
$ImportModule = $PSScriptRoot+"\"+"SpeculationControl.psd1"
$SaveExecutionPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy RemoteSigned -Scope Currentuser -Force
try
{
    Import-Module $ImportModule
}
catch
{
    $errorvar = "Error Importing PS Module"
}
#get settings
$settings = Get-SpeculationControlSettings | Remove-WriteHost
#reset execution policy
Set-ExecutionPolicy $SaveExecutionPolicy -Scope Currentuser -Force

$spectresettings = "BTIHardwarePresent="+$settings.BTIHardwarePresent+", BTIWindowsSupportPresent="+$settings.BTIWindowsSupportPresent+", BTIWindowsSupportEnabled="+$settings.BTIWindowsSupportEnabled+", BTIDisabledBySystemPolicy="+$settings.BTIDisabledBySystemPolicy+", BTIDisabledByNoHardwareSupport="+$settings.BTIDisabledByNoHardwareSupport
#process spectre
if($settings.BTIWindowsSupportPresent -eq $true)
{
    #we have the patch installed / bios is updated
    if($settings.BTIHardwarePresent -eq $true -and $settings.BTIWindowsSupportEnabled)
    {
        #spectre mitigations active
        Write-Host "Spectre Patch installed, BIOS updated, Windows mitigation active. $spectresettings"
    }
    #patch is active / bios is updated / BTI disabled by system policy
    elseif($settings.BTIHardwarePresent -eq $true -and $settings.BTIDisabledBySystemPolicy)
    {
        Write-Host "Spectre Patch installed, BIOS updated, Windows mitigation disabled. $spectresettings"
    }
    else
    {
        Write-Host "Spectre Patch installed, BIOS not updated, Windows --. $spectresettings"
    }
}
else
{
    Write-Host "Spectre Patch not installed, BIOS --, Windows --. $spectresettings"
}

$meltdownsettings = "KVAShadowRequired="+$settings.KVAShadowRequired+", KVAShadowWindowsSupportPresent="+$settings.KVAShadowWindowsSupportPresent+", KVAShadowWindowsSupportEnabled="+$settings.KVAShadowWindowsSupportEnabled+", KVAShadowPcidEnabled="+$settings.KVAShadowPcidEnabled



if($settings.KVAShadowWindowsSupportPresent -eq $true)
{
    #KVA Shadowing patch present
    if($settings.KVAShadowWindowsSupportEnabled -eq $true)
    {
        Write-Host "Meltdown Patch installed, Windows mitigation active. $meltdownsettings"
    }
    else
    {
        Write-Host "Meltdown Patch installed, Windows mitigation disabled. $meltdownsettings"
    }
}
else
{
    Write-Host "Meltdown Patch not installed, Windows --. $meltdownsettings"
}