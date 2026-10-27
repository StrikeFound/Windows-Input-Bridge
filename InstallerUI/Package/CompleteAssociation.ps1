. (Join-Path $PSScriptRoot 'Common.ps1')
$code=1;$logged=$false
try {
    Assert-Administrator;Enter-InputBridgeOperation
    Import-InputBridgeRecoveryAssembly
    $state=Read-InputBridgeState
    if(!$state -or $state.PendingUninstall -or !$state.ControllerAssociation){$code=0}
    else {
        Start-InputBridgeLog 'complete-association';$logged=$true
        $payload=Join-Path $PSScriptRoot 'Payload'
        Assert-InputBridgePayload $payload|Out-Null
        Assert-InputBridgeUsbPackage $payload
        $expected=(Get-FileHash -LiteralPath (Join-Path $payload 'WindowsInputBridge.sys') -Algorithm SHA256).Hash
        if($state.ControllerAssociation.DriverSHA256 -cne $expected){throw 'Un autre paquet a demande cette association. Reouvrir son installeur ; aucune association modifiee.'}
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        if(!$state.ControllerAssociation.Pending -and $state.ControllerAssociation.UsbMigrationVerified){$code=0}
        elseif($state.ControllerAssociation.Pending -and $state.ControllerAssociation.Boot -eq $boot){
            Write-Host 'Windows doit redemarrer avant la suite des associations. Aucun peripherique redemarre par ce script.';$code=3010
        } else {
            $driver=Get-CimInstance Win32_SystemDriver -Filter "Name='WindowsInputBridge'"
            $driverPath=[string]$driver.PathName
            if($driverPath.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)){$driverPath=Join-Path $env:WINDIR $driverPath.Substring(12)}
            $driverPath=$driverPath -replace '^\\\?\?\\',''
            if(!$driver -or $driver.State -ne 'Running' -or (Get-FileHash -LiteralPath $driverPath -Algorithm SHA256).Hash -cne $expected){throw 'Le pilote attendu ne fonctionne pas apres redemarrage. Association differee conservee.'}
            $helper=Join-Path $payload 'InputBridgeExample.exe'
            if((Invoke-InputBridgeSetupHelper $helper @('--status')) -ne 0){throw 'API du pilote indisponible apres redemarrage.'}
            # Include devices first connected after the initial installation
            # in the same protected restoration journal before editing filters.
            Set-InputBridgePhase 'Resume pending device association'
            $state=Save-InputBridgeBaseline
            $script:InputBridgeBeforeSetup=Get-InputBridgeSetupState $helper
            # Finish only the deferred input associations. Do not repeat mapper
            # installation or rebind the root control endpoint on every launch.
            # Older installers could clear Pending when an older loaded backend
            # silently skipped XUSB. Missing proof requires verification again,
            # even when that journal currently says Pending=false.
            $state.ControllerAssociation.Pending=$true
            $state.ControllerAssociation|Add-Member -NotePropertyName UsbMigrationVerified -NotePropertyValue $false -Force
            Write-InputBridgeState $state
            try{$code=Initialize-WindowsInputBridgeControllers $helper}
            catch{$state.ControllerAssociation.LastError=1;Write-InputBridgeState $state;throw}
            Set-InputBridgePhase 'Verify Windows device startup'
            $code=Wait-InputBridgeSetupDevices $helper $script:InputBridgeBeforeSetup -RestartRequested:($code -eq 3010)
            $state=Read-InputBridgeState
            $state.ControllerAssociation.Pending=($code -ne 0)
            $state.ControllerAssociation.UsbMigrationVerified=($code -eq 0)
            $state.ControllerAssociation.Boot=$boot
            $state.ControllerAssociation.LastError=if($code -in @(0,3010)){0}else{$code}
            Write-InputBridgeState $state
            if($code -notin @(0,3010)){throw ('Association des manettes en echec : '+$code)}
            Write-Host $(if($code -eq 0){'Associations completed with the loaded USB backend. Verify capture in diagnostics.'}else{'Association remains pending. Restart Windows normally and reopen this installer to finish loading the driver or controller filters.'})
        }
    }
    if($logged){Complete-InputBridgeOperation $code}
}catch{$code=if($logged){Write-InputBridgeFailure $_}else{Write-Host $_.Exception.ToString();if($script:InputBridgeLastExitCode -notin @(0,3010)){$script:InputBridgeLastExitCode}else{1}}}
finally{try{if($logged){Stop-Transcript|Out-Null}}finally{Exit-InputBridgeOperation}}
exit $code
