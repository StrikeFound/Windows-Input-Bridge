$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$script:InputBridgeService='WindowsInputBridge'
function Assert-Administrator {
    if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights are required.' }
    if(![Environment]::Is64BitProcess) { throw 'Use Windows PowerShell x64.' }
    if([Environment]::OSVersion.Version.Build -lt 16299) { throw 'Windows 10 version 1709 or later, or Windows 11 x64, is required.' }
}
function Get-InputBridgeBoundServices {
    # Read-only preflight for stale per-class and per-device filters. Never
    # remove another edition's service/filter as part of installing this one.
    foreach($guid in @('{4D36E96B-E325-11CE-BFC1-08002BE10318}','{4D36E96F-E325-11CE-BFC1-08002BE10318}','{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}','{D61CA365-5AF4-4486-998B-9DB4734C6CA3}','{05F5CFE2-4733-4950-A6BB-07AAD01A3A84}')){
        $key='HKLM:\SYSTEM\CurrentControlSet\Control\Class\'+$guid
        $properties=Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        foreach($field in @('UpperFilters','LowerFilters')){foreach($filter in @($properties.$field)){if($filter){[pscustomobject]@{Service=[string]$filter;Location=$key+' / '+$field}}}}
    }
    foreach($device in @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop)){
        if(!$device.PNPDeviceID){continue}
        $key='HKLM:\SYSTEM\CurrentControlSet\Enum\'+$device.PNPDeviceID
        $properties=Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        foreach($field in @('UpperFilters','LowerFilters')){foreach($filter in @($properties.$field)){if($filter){[pscustomobject]@{Service=[string]$filter;Location=$key+' / '+$field}}}}
    }
}
function Assert-InputBridgeInstallationBoundary {
    $conflicts=@('Interceptor','InterceptorGamepadController','InterceptorGamepadControllerRelease','InterceptorKeyboardMouse','InterceptorKeyboardMouseRelease','InterceptorRelease','WindowsGamepadBridge','WindowsGamepadFilter','WindowsInputFilter','WindowsKeyboardMouseBridge','WindowsKeyboardMouseFilter')
    foreach($name in $conflicts){
        if(Test-Path -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name)){
            $script:InputBridgeLastExitCode=1638
            throw ('An overlapping input edition is installed or pending removal: '+$name+'. Uninstall it and restart Windows first. Its driver, filters and services were not changed.')
        }
    }
    foreach($binding in @(Get-InputBridgeBoundServices)){
        if($binding.Service -in $conflicts){
            $script:InputBridgeLastExitCode=1638
            throw ('An overlapping input filter remains: '+$binding.Service+' at '+$binding.Location+'. Complete that edition''s uninstall and restart Windows first. No other product was changed.')
        }
    }
}

function Add-InputBridgePackage([string]$Path) {
    $result=Invoke-InputBridgeProcess (Get-InputBridgeWindowsTool 'pnputil.exe') @('/add-driver',$Path) -TimeoutMs 300000
    if($result.ExitCode -notin @(0,3010)){throw ('Driver Store add failed: '+$Path+'; exit '+$result.ExitCode)}
    $script:InputBridgeNeedsReboot=$script:InputBridgeNeedsReboot -or $result.ExitCode -eq 3010
}
function Remove-InputBridgePackage([string]$Name) {
    if($Name -notmatch '^oem[0-9]+\.inf$'){throw 'Invalid owned Driver Store package name.'}
    $result=Invoke-InputBridgeProcess (Get-InputBridgeWindowsTool 'pnputil.exe') @('/delete-driver',$Name,'/uninstall') -TimeoutMs 300000
    if($result.ExitCode -notin @(0,3010)){throw ('Driver Store remove failed: '+$Name+'; exit '+$result.ExitCode)}
    $script:InputBridgeNeedsReboot=$script:InputBridgeNeedsReboot -or $result.ExitCode -eq 3010
}
function Start-InputBridgeLog([string]$Name) {
    $folder=Join-Path $env:ProgramData 'WindowsInputBridge'
    Initialize-InputBridgeStorage
    $script:InputBridgeOperationLabel=$Name
    $script:InputBridgeLogPath=Join-Path $folder ($Name+'-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[Guid]::NewGuid().ToString('N')+'.log')
    Start-Transcript -Path $script:InputBridgeLogPath|Out-Null
    Write-Host ('Setup log: '+$script:InputBridgeLogPath)
}
function Get-InputBridgePackages {
    @(Get-WindowsDriver -Online | Where-Object {
        $_.ProviderName -eq 'InputBridge Project' -and
        [IO.Path]::GetFileName($_.OriginalFileName) -in @('WindowsInputBridgeKeyboard.inf','WindowsInputBridgeMouse.inf','WindowsInputBridgeControl.inf')
    })
}
function Get-InputBridgeSigningMode([string]$Payload) {
    $path=Join-Path $Payload 'Signing.json'
    if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw 'Package signing policy is missing.'}
    $policy=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if($policy.Schema -ne 1 -or $policy.Mode -notin @('Development','Microsoft')){throw 'Politique de signature du paquet invalide.'}
    return [string]$policy.Mode
}
function Assert-InputBridgePayload([string]$Payload,[switch]$AllowDevelopment) {
    $manifest=Get-Content -LiteralPath (Join-Path $Payload 'SHA256.json') -Raw | ConvertFrom-Json
    $mode=Get-InputBridgeSigningMode $Payload
    $names=@('WindowsInputBridge.sys','WindowsInputBridgeKeyboard.inf','WindowsInputBridgeMouse.inf','WindowsInputBridgeControl.inf','WindowsInputBridgeKeyboard.cat','WindowsInputBridgeMouse.cat','WindowsInputBridgeControl.cat','InputBridgeExample.exe')
    if($mode -eq 'Development' -and !$AllowDevelopment){throw 'This product has a new driver identity. Microsoft signing is required before installation. Write the product CAB and import its signed return; no Windows setting was changed.'}
    if(Test-Path -LiteralPath (Join-Path $Payload 'Signing.json')){$names+= 'Signing.json'}
    $clockRequired=@(Get-ChildItem -LiteralPath $Payload -Filter '*Control.inf'|Where-Object {[IO.File]::ReadAllText($_.FullName).Contains('InputSessionClock.sys')}).Count -gt 0
    if($clockRequired){$names+='InputSessionClock.sys'}
    foreach($name in $names) {
        $path=Join-Path $Payload $name
        if(!(Test-Path -LiteralPath $path -PathType Leaf) -or !$manifest.$name -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $manifest.$name){throw "Paquet incomplet ou modifie: $name"}
    }
    foreach($name in @('WindowsInputBridgeKeyboard.inf','WindowsInputBridgeMouse.inf','WindowsInputBridgeControl.inf')){
        $inf=Get-Content -LiteralPath (Join-Path $Payload $name) -Raw
        $servicePattern='(?im)^\s*AddService\s*=\s*'+[regex]::Escape($script:InputBridgeService)+'\s*,'
        if($inf -notmatch $servicePattern){throw "Unexpected service identity: $name"}
    }
    if($mode -eq 'Microsoft') {
        if($clockRequired){$sig=Get-AuthenticodeSignature -LiteralPath (Join-Path $Payload 'InputSessionClock.sys');if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike 'CN=Microsoft Windows Hardware Compatibility Publisher,*'){throw 'Invalid resident clock signature.'}}

        foreach($name in @('WindowsInputBridge.sys','WindowsInputBridgeKeyboard.cat','WindowsInputBridgeMouse.cat','WindowsInputBridgeControl.cat')) {
            $signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $Payload $name)
            if($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
               $signature.SignerCertificate.Subject -ne 'CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US') {
                throw "Signature Microsoft invalide: $name"
            }
        }
    }
    return $mode
}
function Assert-InputBridgeUsbPackage([string]$Payload) {
    # Call only after Assert-InputBridgePayload verified this exact embedded INF,
    # catalog, image and helper. Never apply the new backend requirement to an
    # older signed package merely because its service name matches.
    $inf=Get-Content -LiteralPath (Join-Path $Payload 'WindowsInputBridgeControl.inf') -Raw
    $versions=[regex]::Matches($inf,'(?im)^\s*DriverVer\s*=\s*[^,\r\n]+,\s*(\d+\.\d+\.\d+\.\d+)\s*$')
    if($versions.Count -ne 1 -or [version]$versions[0].Groups[1].Value -lt [version]'0.1.0.0'){
        throw 'This installer requires the Microsoft-signed USB-backend driver package 1.4.17.0 or later. The older embedded package cannot complete this upgrade.'
    }
}
function Invoke-InputBridgeSetupHelper([string]$Helper,[string[]]$Arguments,[int]$TimeoutMs=180000) {
    return [int](Invoke-InputBridgeProcess $Helper $Arguments -TimeoutMs $TimeoutMs).ExitCode
}
function Initialize-WindowsInputBridgeControllers([string]$Helper) {
    # The SDK intentionally refuses to migrate an older loaded upper backend.
    # Installation must preserve its pending state instead of treating skipped
    # XUSB associations as proof that the new package is operational.
    $backend=Invoke-InputBridgeSetupHelper $Helper @('--require-usb-backend')
    if($backend -eq 3010){return 3010}
    if($backend -ne 0){throw ('Cannot verify the loaded USB XUSB backend: '+$backend)}
    $code=Invoke-InputBridgeSetupHelper $Helper @('--init-all','--quiet')
    if($code -notin @(0,3010)){throw ('Controller initialization failed: '+$code)}
    return $code
}
. (Join-Path $PSScriptRoot 'Lifecycle.ps1')

. (Join-Path $PSScriptRoot 'Maintenance.ps1')
