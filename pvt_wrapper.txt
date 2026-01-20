

param(
    [switch]$Silent,
    [switch]$NoBackup,
    [int]$RDPPort,
    [string]$RDPUserName,
    [string]$RDPUserPassword
)

# Definir encoding UTF-8 para evitar caracteres estranhos e logs consistentes
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

# Configurar console para suportar caracteres acentuados
if ($Host.UI.RawUI) {
    try {
        $Host.UI.RawUI.OutputEncoding = [System.Text.Encoding]::UTF8
    } catch {
        # Ignorar se nao conseguir definir
    }
}




# valores padrÃ£o
if (-not $PSBoundParameters.ContainsKey('Silent')) { $Silent = $false }
if (-not $PSBoundParameters.ContainsKey('NoBackup')) { $NoBackup = $false }
if (-not $PSBoundParameters.ContainsKey('RDPPort')) { $RDPPort = 3389 }
if (-not $PSBoundParameters.ContainsKey('RDPUserName')) { $RDPUserName = "Visitante" }
if (-not $PSBoundParameters.ContainsKey('RDPUserPassword')) { $RDPUserPassword = "Visitante@1" }

# ConfiguraÃ§Ãµes globais de erro para um script mais resiliente
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'




# FunÃ§Ã£o de log simplificada e robusta
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Critical')]
        [string]$Level = 'Info'
    )

    # Garante que a variÃ¡vel $Silent exista (caso nÃ£o tenha sido declarada em outro lugar)
    if (-not (Get-Variable -Name Silent -Scope Script -ErrorAction SilentlyContinue)) {
        $Script:Silent = $false
    }

    if (-not $Silent) {
        $color = switch ($Level) {
            'Info'     { 'White' }
            'Warning'  { 'Yellow' }
            'Error'    { 'Red' }
            'Success'  { 'Green' }
            'Critical' { 'DarkRed' }
        }

        # Inclui timestamp para facilitar debug
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "[$timestamp][$Level] $Message" -ForegroundColor $color
    }
}



# FunÃ§Ã£o rÃ¡pida para obter informaÃ§Ãµes do OS
function Get-OSInfo {
    try {
        $OSInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $arch   = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }

        Write-Log "InformaÃ§Ãµes do OS coletadas com sucesso (Build $($OSInfo.CurrentBuild))." -Level Success

        return [PSCustomObject]@{
            CurrentBuild     = $OSInfo.CurrentBuild
            BuildRevision    = $OSInfo.UBR
            FullOSBuild      = if ($OSInfo.UBR) { "$($OSInfo.CurrentBuild).$($OSInfo.UBR)" } else { "$($OSInfo.CurrentBuild)" }
            DisplayVersion   = $OSInfo.DisplayVersion
            InstallationType = $OSInfo.InstallationType
            Architecture     = $arch
        }
    } catch {
        Write-Log "Aviso: Erro ao obter informaÃ§Ãµes detalhadas do OS. $_" -Level Warning
        return $null
    }
}

# FunÃ§Ã£o otimizada para determinar versÃ£o do Windows
function Get-OSVersion {
    try {
        [version]$OSVersion = [System.Environment]::OSVersion.Version
        $OSInfo = Get-OSInfo

        if (-not $OSInfo) {
            # Fallback simples sem registro
            if ($OSVersion.Major -eq 10 -and $OSVersion.Build -ge 22000) { return 'Windows 11' }
            elseif ($OSVersion.Major -eq 10) { return 'Windows 10' }
            elseif ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 1) { return 'Windows 7' }
            else { return 'Unsupported OS' }
        }

        $installationType = $OSInfo.InstallationType

        # DetecÃ§Ã£o por versÃ£o
        if ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 1) {
            return 'Windows 7'
        }
        elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -lt 22000 -and ($installationType -eq 'Client')) {
            return 'Windows 10'
        }
        elseif ($OSVersion.Major -eq 10 -and $OSVersion.Build -ge 22000 -and ($installationType -eq 'Client')) {
            return 'Windows 11'
        }
        elseif ($installationType -eq 'Server') {
            # Mais especÃ­fico para Server
            switch ($OSVersion.Build) {
                20348 { return 'Windows Server 2022' }
                {$_ -ge 14393 -and $_ -lt 22000} { return 'Windows Server 2016/2019' }
                default { return 'Windows Server' }
            }
        }
        else {
            return 'Unsupported OS'
        }
    } catch {
        Write-Log "Aviso: Usando detecÃ§Ã£o bÃ¡sica do OS. $_" -Level Warning
        return 'Unsupported OS'
    }
}


# FunÃ§Ã£o para parar serviÃ§os RDP de forma agressiva
function Get-TermsrvDllVersionInfo {
    param([string]$FilePath)

    try {
        if (-not (Test-Path -Path $FilePath -PathType Leaf)) { return $null }
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
        if ($info) {
            $versionText = '{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart
            return [PSCustomObject]@{
                VersionObject = [version]$versionText
                VersionText   = $versionText
            }
        }
    } catch {
        Write-Log "Aviso: Falha ao obter vers  o do termsrv.dll. $_" -Level Warning
    }

    return $null
}

function Convert-RdpWrapIniToHashtable {
    param([string]$IniContent)

    $sections = @{}
    $current = $null

    foreach ($rawLine in ($IniContent -split "`r?`n")) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith(';')) { continue }

        if ($line -match '^\[(.+)\]$') {
            $current = $matches[1].Trim()
            if (-not $sections.ContainsKey($current)) { $sections[$current] = @{} }
            continue
        }

        if (-not $current -or (-not $line.Contains('='))) { continue }

        $pair = $line.Split('=', 2)
        if ($pair.Count -ne 2) { continue }

        $key = $pair[0].Trim()
        $value = $pair[1].Trim()
        if ($value -match '^(?<val>[^;]+)') { $value = $matches['val'].Trim() }

        if ($key) { $sections[$current][$key] = $value }
    }

    return $sections
}

function Convert-HexStringToByteArray {
    param([string]$HexValue)

    $clean = ($HexValue -replace '\s+', '')
    if (-not $clean) { throw "Valor hexadecimal vazio." }
    if ($clean.Length % 2 -ne 0) { throw "Valor hexadecimal '$HexValue' possui numero impar de caracteres." }

    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Resolve-RdpWrapCodeValue {
    param(
        [string]$CodeToken,
        [hashtable]$PatchCodes
    )

    if ($PatchCodes -and $PatchCodes.ContainsKey($CodeToken)) {
        return $PatchCodes[$CodeToken]
    }

    return $CodeToken
}

function Convert-RdpWrapOffset {
    param([string]$OffsetValue)

    $clean = $OffsetValue.Trim()
    if ($clean -match '^0[xX](?<hex>[0-9A-Fa-f]+)$') { return [Convert]::ToInt64($matches.hex, 16) }
    if ($clean -match '^[0-9A-Fa-f]+$') { return [Convert]::ToInt64($clean, 16) }
    if ($clean -match '^\d+$') { return [int64]$clean }

    throw "Offset invalido: $OffsetValue"
}

function Get-RdpWrapConfiguration {
    param([string]$ConfigUrl = 'https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/master/rdpwrap.ini')

    try {
        Write-Log "Baixando rdpwrap.ini atualizado..." -Level Info
        $response = Invoke-WebRequest -Uri $ConfigUrl -UseBasicParsing -ErrorAction Stop
        return Convert-RdpWrapIniToHashtable -IniContent $response.Content
    } catch {
        Write-Log "Aviso: Falha ao baixar rdpwrap.ini. $_" -Level Warning
        return $null
    }
}

function Get-RdpWrapPatchPlan {
    param(
        [hashtable]$IniData,
        [string]$VersionText,
        [string]$ArchitectureKey
    )

    if (-not $IniData -or -not $VersionText) { return $null }

    $sectionName = $VersionText
    if (-not $IniData.ContainsKey($sectionName)) {
        $segments = $VersionText -split '\.'
        if ($segments.Length -ge 3) {
            $prefix = ($segments[0..2] -join '.')
            $candidates = $IniData.Keys | Where-Object {
                $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_.StartsWith("$prefix.")
            }
            if ($candidates) {
                $sectionName = ($candidates | Sort-Object {[version]$_} -Descending | Select-Object -First 1)
                Write-Log "Aviso: Usando entrada de vers  o aproximada '$sectionName' para $VersionText." -Level Warning
            }
        }
    }

    if (-not $IniData.ContainsKey($sectionName)) { return $null }

    $section = $IniData[$sectionName]
    $patchCodes = if ($IniData.ContainsKey('PatchCodes')) { $IniData['PatchCodes'] } else { @{} }
    $entries = @()

    foreach ($key in $section.Keys) {
        if ($key -notmatch "^(?<name>.+)Patch\.$ArchitectureKey$") { continue }

        $shouldPatch = $section[$key]
        if ($shouldPatch -ne '1') { continue }

        $baseName = $matches.name
        $offsetKey = "$baseName`Offset.$ArchitectureKey"
        $codeKey = "$baseName`Code.$ArchitectureKey"

        if (-not ($section.ContainsKey($offsetKey) -and $section.ContainsKey($codeKey))) {
            Write-Log "Aviso: Entrada '$baseName' incompleta para $ArchitectureKey em $sectionName." -Level Warning
            continue
        }

        try {
            $offset = Convert-RdpWrapOffset -OffsetValue $section[$offsetKey]
            $codeValue = Resolve-RdpWrapCodeValue -CodeToken $section[$codeKey] -PatchCodes $patchCodes
            $bytes = Convert-HexStringToByteArray -HexValue $codeValue

            $entries += [PSCustomObject]@{
                Name   = $baseName
                Offset = $offset
                Bytes  = $bytes
            }
        } catch {
            Write-Log "Aviso: Falha ao preparar patch '$baseName' ($ArchitectureKey). $_" -Level Warning
        }
    }

    if (-not $entries) { return $null }

    return [PSCustomObject]@{
        Version = $sectionName
        Entries = $entries | Sort-Object Offset
    }
}

function Stop-TermService {
    try {
        Write-Log "Parando serviÃ§os de Ãrea de Trabalho Remota..." -Level Info
        
        # Parar mÃºltiplos serviÃ§os relacionados
        $services = @('TermService', 'UmRdpService', 'SessionEnv')
        foreach ($serviceName in $services) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service -and $service.Status -ne 'Stopped') {
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                    Write-Log "ServiÃ§o '$serviceName' parado." -Level Info
                }
            } catch { Write-Log "Aviso: Falha ao parar '$serviceName'. Continuando..." -Level Warning }
        }
        
        # Aguardar serviÃ§os pararem
        Start-Sleep -Seconds 2
        
        # ForÃ§ar kill de processos que podem estar usando o arquivo (apenas processos menos crÃ­ticos)
        $processesToKill = Get-Process | Where-Object { 
            ($_.ProcessName -eq 'svchost' -or $_.ProcessName -eq 'dwm' -or $_.ProcessName -eq 'spoolsv') -and 
            $_.Modules -and ($_.Modules | Where-Object { $_.FileName -like "*termsrv.dll*" })
        }
        if ($processesToKill) {
            Write-Log "Tentando liberar handles do termsrv.dll de processos..." -Level Info
            foreach ($process in $processesToKill) {
                try {
                    Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue
                    Write-Log "Processo $($process.ProcessName) (PID: $($process.Id)) parado." -Level Info
                } catch { Write-Log "Aviso: Falha ao parar processo $($process.ProcessName). Pode exigir reinÃ­cio." -Level Warning }
            }
        }
        
        # Tentar liberar handles do arquivo (se handle.exe estiver disponÃ­vel)
        try {
            if (Get-Command "handle.exe" -ErrorAction SilentlyContinue) {
                handle.exe -accepteula -p svchost -u termsrv.dll 2>$null | Out-Null
                handle.exe -accepteula -p services -u termsrv.dll 2>$null | Out-Null
                Write-Log "Tentativa de liberar handles do termsrv.dll com handle.exe." -Level Info
            }
        } catch { Write-Log "Aviso: handle.exe nÃ£o disponÃ­vel ou falhou." -Level Warning }
        
        Write-Log "ServiÃ§os de Ãrea de Trabalho Remota processados." -Level Success
        return $true
    } catch {
        Write-Log "Aviso: Problema ao parar serviÃ§os de Ãrea de Trabalho Remota - continuando. Erro: $($_.Exception.Message)" -Level Warning
        return $true
    }
}


function Invoke-InstantDropAndPatch {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TermsrvDllAsFile,
        [Parameter(Mandatory=$true)]
        [string]$TermsrvDllAsPatch
    )

    if (-not (Test-Path -Path $TermsrvDllAsPatch -PathType Leaf)) {
        Write-Host "[ERRO] Arquivo de patch nÃ£o encontrado: $TermsrvDllAsPatch"
        return $false
    }

    $targetExists = Test-Path -Path $TermsrvDllAsFile -PathType Leaf
    if (-not $targetExists) {
        Write-Host "[AVISO] Arquivo alvo nÃ£o existe, serÃ¡ criado: $TermsrvDllAsFile"
    }

    Write-Host "[INFO] Executando PATCH instantÃ¢neo do termsrv.dll..."
    $killJob = $null
    $success = $false

    try {
        $killJob = Start-Job -ScriptBlock {
            param($serviceName)
            for ($i = 0; $i -lt 50; $i++) {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service -and $service.Status -eq 'Running') {
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Milliseconds 100
            }
        } -ArgumentList 'TermService'

        $null = Stop-TermService
        Start-Sleep -Milliseconds 200

        $targetDir = Split-Path -Parent $TermsrvDllAsFile
        if (-not $targetDir) { $targetDir = [Environment]::GetFolderPath('System') }

        if (-not (Test-Path -Path $targetDir)) {
            try { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null } catch { }
        }

        if ($targetExists) {
            try {
                $temp = Join-Path -Path $targetDir -ChildPath ("{0}.old" -f (Split-Path -Leaf $TermsrvDllAsFile))
                Move-Item -Path $TermsrvDllAsFile -Destination $temp -Force -ErrorAction Stop
                Copy-Item -Path $TermsrvDllAsPatch -Destination $TermsrvDllAsFile -Force -ErrorAction Stop
                Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue
                Write-Host "[SUCESSO] Patch aplicado (Move rÃ¡pido)"
                $success = $true
            } catch {
                Write-Host "[AVISO] Tentativa 1 falhou: $($_.Exception.Message)"
            }
        }

        if (-not $success) {
            try {
                Copy-Item -Path $TermsrvDllAsPatch -Destination $TermsrvDllAsFile -Force -ErrorAction Stop
                Write-Host "[SUCESSO] Patch aplicado (CÃ³pia forÃ§ada)"
                $success = $true
            } catch {
                Write-Host "[AVISO] Tentativa 2 falhou: $($_.Exception.Message)"
            }
        }

        if (-not $success) {
            try {
                [System.IO.File]::Copy($TermsrvDllAsPatch, $TermsrvDllAsFile, $true)
                Write-Host "[SUCESSO] Patch aplicado (System.IO)"
                $success = $true
            } catch {
                Write-Host "[ERRO] Tentativa 3 falhou: $($_.Exception.Message)"
            }
        }
    } finally {
        if ($killJob -ne $null) {
            try {
                Stop-Job -Job $killJob -Force -ErrorAction SilentlyContinue
                Remove-Job -Job $killJob -ErrorAction SilentlyContinue
            } catch { }
        }
    }

    return $success
}
function Update-TermsrvDll {
    param (
        [Parameter(Mandatory)] [string]$TermsrvDllAsFile,
        [Parameter(Mandatory)] [string]$TermsrvDllAsPatch,
        [Parameter(Mandatory)] [string]$TermsrvDllAsText,
        [Parameter(Mandatory)] [System.Security.AccessControl.FileSecurity]$TermsrvAclObject,
        [Parameter(Mandatory)] [scriptblock]$PatchLogic,
        [hashtable]$PatchParams
    )

    try {
        $invokeParams = @{ DllAsText = $TermsrvDllAsText }
        if ($PatchParams) {
            foreach ($key in $PatchParams.Keys) {
                $invokeParams[$key] = $PatchParams[$key]
            }
        }

        $dllAsTextReplaced = & $PatchLogic @invokeParams
        $patchSuccess = $false

        if ($dllAsTextReplaced -ne $TermsrvDllAsText) {
            Write-Host "[INFO] PadrÃ£o encontrado, preparando patch..."

            [byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'
            [System.IO.File]::WriteAllBytes($TermsrvDllAsPatch, $dllAsBytesReplaced)

            $patchSuccess = Invoke-InstantDropAndPatch -TermsrvDllAsFile $TermsrvDllAsFile -TermsrvDllAsPatch $TermsrvDllAsPatch

            if (-not $patchSuccess) {
                Write-Host "[AVISO] Tentando mÃ©todo de emergÃªncia..."
                for ($i = 1; $i -le 3; $i++) {
                    try {
                        $null = Stop-TermService
                        Start-Sleep -Milliseconds 50
                        Copy-Item -Path $TermsrvDllAsPatch -Destination $TermsrvDllAsFile -Force -ErrorAction Stop
                        Write-Host "[SUCESSO] Patch aplicado na tentativa de emergÃªncia $i"
                        $patchSuccess = $true
                        break
                    } catch {
                        if ($i -eq 3) { Write-Host "[ERRO] Todas as tentativas falharam." }
                    }
                }
            }

            if (-not $patchSuccess) {
                Write-Host "[AVISO] Agendando patch para prÃ³xima reinicializaÃ§Ã£o..."
                $pendingOps = @("\??\$TermsrvDllAsFile", "\??\$TermsrvDllAsPatch")
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $pendingOps -PropertyType MultiString -Force | Out-Null
                $runOnceCmd = "cmd.exe /c copy /y `"$TermsrvDllAsPatch`" `"$TermsrvDllAsFile`" & del `"$TermsrvDllAsPatch`""
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "RDPPatch" -Value $runOnceCmd -Force
            }
        }
        elseif ($TermsrvDllAsText -match 'B8 00 01 00 00') {
            Write-Host "[INFO] Arquivo jÃ¡ estÃ¡ patchado"
        }
        else {
            Write-Host "[AVISO] PadrÃ£o nÃ£o encontrado, versÃ£o pode nÃ£o ser suportada"
        }

        try {
            Set-Acl -Path $TermsrvDllAsFile -AclObject $TermsrvAclObject -ErrorAction SilentlyContinue
            Write-Host "[INFO] PermissÃµes restauradas"
        } catch {
            Write-Host "[AVISO] NÃ£o foi possÃ­vel restaurar permissÃµes: $($_.Exception.Message)"
        }

        try {
            Start-Service TermService -ErrorAction SilentlyContinue
            Write-Host "[INFO] TermService reiniciado"
        } catch {
            Write-Host "[AVISO] TermService pode reiniciar automaticamente"
        }

        return $true
    } catch {
        Write-Host "[ERRO] Falha em Update-TermsrvDll: $($_.Exception.Message)"
        return $false
    }
}


# Funcao para criar e configurar usuario RDP
function Add-RDPUserAccount {
    param(
        [string]$userName,
        [string]$userPassword
    )
    try {
        Write-Host "[Info] Configurando usuario RDP '$userName'..."

        $securePassword = $userPassword | ConvertTo-SecureString -AsPlainText -Force

        try {
            New-LocalUser -Name $userName -Password $securePassword -ErrorAction Stop
            Write-Host "[Sucesso] Usuario '$userName' criado."
        } catch {
            Write-Host "[Aviso] Nao foi possivel criar o usuario '$userName'. Pode ja existir. Erro: $($_.Exception.Message)"
        }

        $groups = @("Remote Desktop Users", "Usuarios da Area de Trabalho Remota", "Administradores", "Administrators")
        foreach ($group in $groups) {
            try {
                Add-LocalGroupMember -Group $group -Member $userName -ErrorAction Stop
                Write-Host "[Sucesso] Usuario '$userName' adicionado ao grupo '$group'."
            } catch {
                Write-Host "[Aviso] Falha ao adicionar usuario '$userName' ao grupo '$group'. Erro: $($_.Exception.Message)"
            }
        }

        $regPathSpecialAccounts = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts"
        $regPathUserList = "$regPathSpecialAccounts\UserList"
        try {
            if (-not (Test-Path $regPathSpecialAccounts)) { New-Item -Path $regPathSpecialAccounts -Force | Out-Null }
            if (-not (Test-Path $regPathUserList)) { New-Item -Path $regPathUserList -Force | Out-Null }
            New-ItemProperty -Path $regPathUserList -Name $userName -Value 0 -PropertyType DWord -Force | Out-Null
            Write-Host "[Info] Usuario '$userName' ocultado da tela de login."
        } catch {
            Write-Host "[Aviso] Falha ao configurar registro para ocultar usuario '$userName'. Erro: $($_.Exception.Message)"
        }

        Write-Host "[Sucesso] Configuracao do usuario RDP concluida."
        return $true
    } catch {
        Write-Host "[Erro] Add-RDPUserAccount falhou: $($_.Exception.Message)"
        return $false
    }
}

# Funcao para habilitar RDP e definir configuracoes basicas
function Enable-RemoteDesktop {
    param([int]$Port = 3389)
    try {
        Write-Host "[Info] Habilitando e configurando RDP..."

        # Habilitar RDP
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Force

        # Garantir que RDP-Tcp esta ativo
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fEnableWinStation" -Value 1 -Force

        # Definir porta
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp" -Name "PortNumber" -Value $Port -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value $Port -Force

        # Config seguranca basica (sem NLA)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 1 -Force

        # Iniciar servico principal
        try {
            Set-Service -Name "TermService" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "TermService" -ErrorAction SilentlyContinue
            Write-Host "[Info] Servico TermService iniciado."
        } catch {
            Write-Host "[Aviso] Falha ao iniciar TermService: $($_.Exception.Message)"
        }

        Write-Host "[Sucesso] RDP habilitado na porta $Port"
        return $true
    } catch {
        Write-Host "[Aviso] Problema ao habilitar RDP: $($_.Exception.Message)"
        return $true
    }
}




function Configure-StealthMode {
    Write-Host "[CRITICO] MODO FURTIVO ATIVADO: Desabilitando todos os logs e rastros possiveis!"
    Write-Host "[CRITICO] ATENCAO: Esta configuracao e EXTREMAMENTE AGRESSIVA e deve ser usada apenas em ambiente de teste."
    Write-Host "[INFO] Uma reinicializacao e recomendada apos a execucao."

    # 1. Desabilitar Logs de Auditoria
    try {
        Write-Host "[INFO] Desabilitando politicas de auditoria..."
        auditpol /set /category:"*" /success:disable /failure:disable >$null 2>&1
        Write-Host "[OK] Politicas de auditoria desabilitadas."
    } catch { Write-Host "[AVISO] Falha ao desabilitar politicas de auditoria. Erro: $($_.Exception.Message)" }

    # 2. Desabilitar Logging do PowerShell
    $psPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    if (-not (Test-Path $psPolicyPath)) { New-Item -Path $psPolicyPath -Force | Out-Null }

    try {
        $sbLogPath = "$psPolicyPath\ScriptBlockLogging"
        if (-not (Test-Path $sbLogPath)) { New-Item -Path $sbLogPath -Force | Out-Null }
        New-ItemProperty -Path $sbLogPath -Name "EnableScriptBlockLogging" -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Host "[OK] Script Block Logging desabilitado."
    } catch { Write-Host "[AVISO] Falha ao desabilitar Script Block Logging. Erro: $($_.Exception.Message)" }

    try {
        $moduleLogPath = "$psPolicyPath\ModuleLogging"
        if (-not (Test-Path $moduleLogPath)) { New-Item -Path $moduleLogPath -Force | Out-Null }
        New-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -Value 0 -PropertyType DWord -Force | Out-Null
        Remove-ItemProperty -Path $moduleLogPath -Name "ModuleNames" -ErrorAction SilentlyContinue
        Write-Host "[OK] Module Logging desabilitado."
    } catch { Write-Host "[AVISO] Falha ao desabilitar Module Logging. Erro: $($_.Exception.Message)" }

    try {
        $transcriptPath = "$psPolicyPath\Transcription"
        if (-not (Test-Path $transcriptPath)) { New-Item -Path $transcriptPath -Force | Out-Null }
        New-ItemProperty -Path $transcriptPath -Name "EnableTranscripting" -Value 0 -PropertyType DWord -Force | Out-Null
        Remove-ItemProperty -Path $transcriptPath -Name "OutputDirectory" -ErrorAction SilentlyContinue
        Write-Host "[OK] Transcricao de sessoes PowerShell desabilitada."
    } catch { Write-Host "[AVISO] Falha ao desabilitar Transcricao. Erro: $($_.Exception.Message)" }

    # Limpar historico do PS
    try {
        $psReadLineHistoryPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
        if (Test-Path $psReadLineHistoryPath) {
            Remove-Item $psReadLineHistoryPath -Force -ErrorAction SilentlyContinue
            Write-Host "[OK] Historico do PSReadline limpo."
        }
        Clear-History -ErrorAction SilentlyContinue
        Write-Host "[OK] Historico da sessao PowerShell limpo."
    } catch { Write-Host "[AVISO] Falha ao limpar historico do PowerShell. Erro: $($_.Exception.Message)" }

    # 3. Desabilitar e limpar Event Logs
    Write-Host "[CRITICO] Desabilitando e limpando todos os Event Logs (inclui SEGURANCA)."
    try {
        $allEventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object {$_.LogName -notmatch "ForwardedEvents|HardwareEvents"}
        foreach ($log in $allEventLogs) {
            try {
                if ($log.IsEnabled) {
                    wevtutil.exe sl "$($log.LogName)" /e:false 2>$null
                    Write-Host "[OK] Log $($log.LogName) desabilitado."
                }
                wevtutil.exe cl "$($log.LogName)" 2>$null
                Write-Host "[OK] Log $($log.LogName) limpo."
            } catch {
                Write-Host "[AVISO] Falha ao processar log $($log.LogName). Erro: $($_.Exception.Message)"
            }
        }
    } catch { Write-Host "[ERRO] Nao foi possivel processar Event Logs. Erro: $($_.Exception.Message)" }

# --- 4. Limpar HistÃ³rico de ConexÃµes RDP (cliente-side) ---
    try {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Terminal Server Client\Default" -Name "MRU*" -ErrorAction SilentlyContinue
        Remove-Item -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "âœ“ HistÃ³rico de conexÃµes RDP (cliente-side) limpo." -Level Success
    } catch { Write-Log "Aviso: Falha ao limpar histÃ³rico de RDP client-side. Erro: $($_.Exception.Message)" -Level Warning }

    # --- 5. Desabilitar Telemetria e DiagnÃ³stico ---
    # Desabilitar Activity History
    try {
        $systemPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $systemPolicyPath)) { New-Item -Path $systemPolicyPath -Force | Out-Null }
        foreach ($name in @('EnableActivityFeed','PublishUserActivities','UploadUserActivities')) {
            New-ItemProperty -Path $systemPolicyPath -Name $name -Value 0 -PropertyType DWord -Force | Out-Null
        }
        Write-Log "âœ“ HistÃ³rico de Atividades do Windows desabilitado." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar HistÃ³rico de Atividades. Erro: $($_.Exception.Message)" -Level Warning }

    # Desabilitar experimentos (Preview Builds)
    try {
        $previewPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
        if (-not (Test-Path $previewPath)) { New-Item -Path $previewPath -Force | Out-Null }
        New-ItemProperty -Path $previewPath -Name "AllowBuildPreview" -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Log "âœ“ Telemetria de Preview Builds desabilitada." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar Telemetria de Preview Builds. Erro: $($_.Exception.Message)" -Level Warning }

    # Desabilitar telemetria de aplicativos
    try {
        $dataCollectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (-not (Test-Path $dataCollectionPath)) { New-Item -Path $dataCollectionPath -Force | Out-Null }
        New-ItemProperty -Path $dataCollectionPath -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Log "âœ“ Telemetria de aplicativos desabilitada." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar Telemetria de aplicativos. Erro: $($_.Exception.Message)" -Level Warning }

    # Desabilitar CEIP (Customer Experience Improvement Program)
    try {
        $sqmPath = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
        if (-not (Test-Path $sqmPath)) { New-Item -Path $sqmPath -Force | Out-Null }
        New-ItemProperty -Path $sqmPath -Name "CEIPEnable" -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Log "âœ“ CEIP desabilitado." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar CEIP. Erro: $($_.Exception.Message)" -Level Warning }

    # Desabilitar MRT (Malicious Software Removal Tool) reporting
    try {
        $mrtPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"
        if (-not (Test-Path $mrtPolicyPath)) { New-Item -Path $mrtPolicyPath -Force | Out-Null }
        New-ItemProperty -Path $mrtPolicyPath -Name "DontReportInfectionInformation" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $mrtPolicyPath -Name "DontOfferThroughWUAU" -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Log "âœ“ RelatÃ³rios do MRT desabilitados." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar RelatÃ³rios do MRT. Erro: $($_.Exception.Message)" -Level Warning }

    # Desabilitar Prefetch/Superfetch (SysMain) para reduzir rastros de execuÃ§Ã£o de programas
    try {
        Set-Service -Name SysMain -StartupType Disabled -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log "âœ“ Prefetch/Superfetch (SysMain) desabilitado." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar Prefetch/Superfetch. Erro: $($_.Exception.Message)" -Level Warning }

    # Limpar dados do Monitor de Confiabilidade (Reliability Monitor)
    try {
        Remove-Item "$env:ProgramData\Microsoft\RAC\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\AppCompatCache" -Name "*" -ErrorAction SilentlyContinue
        Write-Log "âœ“ Dados do Monitor de Confiabilidade (RAC) e cache de compatibilidade limpos." -Level Success
    } catch { Write-Log "Aviso: Falha ao limpar dados do Monitor de Confiabilidade. Erro: $($_.Exception.Message)" -Level Warning }

    # Desabilitar Windows Error Reporting (WER)
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Force -ErrorAction SilentlyContinue
        Set-Service -Name "WerSvc" -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "âœ“ Windows Error Reporting desabilitado." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar Windows Error Reporting. Erro: $($_.Exception.Message)" -Level Warning }
    
    # Desabilitar Connected User Experiences and Telemetry (DiagTrack)
    try {
        Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name "DiagTrack" -Force -ErrorAction SilentlyContinue
        Write-Log "âœ“ ServiÃ§o 'Connected User Experiences and Telemetry' (DiagTrack) desabilitado." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar DiagTrack. Erro: $($_.Exception.Message)" -Level Warning }

    # Desabilitar ServiÃ§o de Roteamento de NotificaÃ§Ã£o de Eventos do Windows (Wecsvc) - pode logar eventos de subsistema
    try {
        Set-Service -Name "Wecsvc" -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name "Wecsvc" -Force -ErrorAction SilentlyContinue
        Write-Log "âœ“ ServiÃ§o 'Event Collector' (Wecsvc) desabilitado." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar Wecsvc. Erro: $($_.Exception.Message)" -Level Warning }

    # --- 6. Limpar Rastros de UsuÃ¡rio (mantendo cautela com temporÃ¡rios globais) ---
    try {
        # Limpar pasta de itens recentes
        Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force -ErrorAction SilentlyContinue
        # Limpar Jump Lists para programas (itens fixados no menu iniciar/barra de tarefas)
        Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "âœ“ Arquivos recentes e Jump Lists limpos." -Level Success
    } catch { Write-Log "Aviso: Falha ao limpar arquivos recentes/Jump Lists. Erro: $($_.Exception.Message)" -Level Warning }

    # Limpar apenas a lixeira (reciclar) - para a conta do Administrador
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Log "âœ“ Lixeira (administrador) esvaziada." -Level Success
    } catch { Write-Log "Aviso: Falha ao esvaziar lixeira. Erro: $($_.Exception.Message)" -Level Warning }

    # Limpar Minidumps e MEMORY.DMP
    try {
        Remove-Item "$env:SystemRoot\Minidump\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:SystemRoot\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
        Write-Log "âœ“ Minidumps e MEMORY.DMP limpos." -Level Success
    } catch { Write-Log "Aviso: Falha ao limpar Minidumps/MEMORY.DMP. Erro: $($_.Exception.Message)" -Level Warning }

    # Desabilitar Registro de Dispositivos Conectados (USB, etc.) via PnP-Log
    try {
        wevtutil.exe sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:false 2>$null
        wevtutil.exe cl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" 2>$null
        wevtutil.exe sl "Microsoft-Windows-DeviceSetupManager/Admin" /e:false 2>$null
        wevtutil.exe cl "Microsoft-Windows-DeviceSetupManager/Admin" 2>$null
        Write-Log "âœ“ Registro de dispositivos PnP desabilitado e limpo." -Level Success
    } catch { Write-Log "Aviso: Falha ao desabilitar registro de dispositivos. Erro: $($_.Exception.Message)" -Level Warning }

    # Configurar o Page File (arquivo de paginaÃ§Ã£o) para ser limpo no desligamento
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "âœ“ Configurado para limpar o arquivo de paginaÃ§Ã£o no desligamento." -Level Success
    } catch { Write-Log "Aviso: Falha ao configurar a limpeza do arquivo de paginaÃ§Ã£o. Erro: $($_.Exception.Message)" -Level Warning }
    


    Write-Host "[CRITICO] MODO FURTIVO: Configuracao concluida! Reinicie o sistema."
    return $true
}

# FunÃ§Ã£o para configurar UAC (User Account Control) para compatibilidade RDP
function Set-UACConfiguration {
    try {
        Write-Host "(Info) Configurando UAC para compatibilidade RDP..."
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 0 -Force
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force
        Write-Host "(Success) UAC configurado com sucesso."
        return $true
    } catch {
        Write-Host "(Warning) Falha ao configurar UAC. Erro: $($_.Exception.Message)"
        return $true # fallback para nÃ£o quebrar o fluxo
    }
} # Fim da funÃ§Ã£o Set-UACConfiguration


# FunÃ§Ã£o para resolver restriÃ§Ãµes de conta RDP e multi-sessÃ£o
function Fix-RDPAccountRestrictions {
    try {
        Write-Host "(Info) Corrigindo restriÃ§Ãµes de conta RDP e sessÃµes mÃºltiplas..."

        # 1. Permitir senhas em branco via RDP
        try {
            $securityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Set-ItemProperty -Path $securityPath -Name "LimitBlankPasswordUse" -Value 0 -Force
            Write-Host "(Success) Senhas em branco permitidas via RDP."
        } catch {
            Write-Host "(Warning) Falha ao permitir senhas em branco. Erro: $($_.Exception.Message)"
        }

        # 2. Desabilitar Credential Guard
        try {
            $credGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
            if (Test-Path $credGuardPath) {
                Set-ItemProperty -Path $credGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 0 -Force
                Set-ItemProperty -Path $credGuardPath -Name "RequirePlatformSecurityFeatures" -Value 0 -Force
            }

            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 0 -Force
            Write-Host "(Success) Credential Guard desabilitado (se ativo)."
        } catch {
            Write-Host "(Warning) Credential Guard pode ainda estar ativo. Erro: $($_.Exception.Message)"
        }

        # 3. Ajustar delegaÃ§Ã£o de credenciais
        try {
            $delegationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
            if (-not (Test-Path $delegationPath)) { New-Item -Path $delegationPath -Force | Out-Null }

            Set-ItemProperty -Path $delegationPath -Name "RestrictedRemoteAdministration" -Value 0 -Force
            Set-ItemProperty -Path $delegationPath -Name "DenyDefaultCredentials" -Value 0 -Force

            Write-Host "(Success) DelegaÃ§Ã£o de credenciais liberada."
        } catch {
            Write-Host "(Warning) Falha ao configurar delegaÃ§Ã£o de credenciais. Erro: $($_.Exception.Message)"
        }

        # 4. Garantir direitos de logon RDP
        try {
            net localgroup "Remote Desktop Users" "Users" /add 2>$null | Out-Null
            net localgroup "Remote Desktop Users" "Administrators" /add 2>$null | Out-Null
            Write-Host "(Success) Grupos adicionados ao Remote Desktop Users."
        } catch {
            Write-Host "(Warning) Falha ao adicionar grupos RDP. Erro: $($_.Exception.Message)"
        }

        # 5. Desabilitar Network Level Authentication (NLA)
        try {
            $nlaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            Set-ItemProperty -Path $nlaPath -Name "UserAuthentication" -Value 0 -Force
            Set-ItemProperty -Path $nlaPath -Name "SecurityLayer" -Value 0 -Force
            Write-Host "(Success) Network Level Authentication desabilitado."
        } catch {
            Write-Host "(Warning) Falha ao desabilitar NLA. Erro: $($_.Exception.Message)"
        }

        # 6. Permitir mÃºltiplas sessÃµes por usuÃ¡rio
        try {
            $tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            if (-not (Test-Path $tsPath)) { New-Item -Path $tsPath -Force | Out-Null }

            Set-ItemProperty -Path $tsPath -Name "fSingleSessionPerUser" -Value 0 -Force
            Set-ItemProperty -Path $tsPath -Name "AllowMultipleTSSessions" -Value 1 -Force
            Set-ItemProperty -Path $tsPath -Name "MaxInstanceCount" -Value 999999 -Force

            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fSingleSessionPerUser" -Value 0 -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "MaxInstanceCount" -Value 999999 -Force

            Write-Host "(Success) MÃºltiplas sessÃµes por usuÃ¡rio habilitadas."
        } catch {
            Write-Host "(Warning) Falha ao habilitar mÃºltiplas sessÃµes. Erro: $($_.Exception.Message)"
        }

        # 7. Remover timeouts de sessÃ£o
        try {
            $winStationsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            Set-ItemProperty -Path $winStationsPath -Name "MaxConnectionTime" -Value 0 -Force
            Set-ItemProperty -Path $winStationsPath -Name "MaxDisconnectionTime" -Value 0 -Force
            Set-ItemProperty -Path $winStationsPath -Name "MaxIdleTime" -Value 0 -Force
            Set-ItemProperty -Path $winStationsPath -Name "fInheritMaxSessionTime" -Value 0 -Force
            Set-ItemProperty -Path $winStationsPath -Name "fInheritMaxDisconnectionTime" -Value 0 -Force
            Set-ItemProperty -Path $winStationsPath -Name "fInheritMaxIdleTime" -Value 0 -Force

            Write-Host "(Success) Timeouts RDP removidos."
        } catch {
            Write-Host "(Warning) Falha ao remover timeouts. Erro: $($_.Exception.Message)"
        }

        # 8. Ajustar ListenerAdapter
        try {
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters" -Name "ListenerAdapter" -ErrorAction SilentlyContinue
            Write-Host "(Success) ListenerAdapter removido (se presente)."
        } catch {
            Write-Host "(Warning) Falha ao remover ListenerAdapter. Erro: $($_.Exception.Message)"
        }

        Write-Host "(Success) === CorreÃ§Ãµes de restriÃ§Ãµes RDP aplicadas ==="
        return $true
    } catch {
        Write-Host "(Error) Erro crÃ­tico ao corrigir restriÃ§Ãµes RDP: $($_.Exception.Message)"
        return $false
    }
} # Fim da funÃ§Ã£o Fix-RDPAccountRestrictions


# FunÃ§Ã£o para configurar regras de Firewall para RDP
function Configure-Firewall {
    param([int]$Port = 3389)

    try {
        Write-Host "(Info) Configurando firewall para RDP na porta $Port..."

        # Remover regras antigas
        Get-NetFirewallRule -DisplayName "RDP-${Port}-TCP" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false
        Get-NetFirewallRule -DisplayName "RDP-${Port}-UDP" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false

        # Criar novas regras
        New-NetFirewallRule -DisplayName "RDP-${Port}-TCP" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Any -ErrorAction Stop
        New-NetFirewallRule -DisplayName "RDP-${Port}-UDP" -Direction Inbound -Protocol UDP -LocalPort $Port -Action Allow -Profile Any -ErrorAction Stop

        Write-Host "(Success) Regras de firewall aplicadas para RDP na porta $Port."
        return $true
    } catch {
        Write-Host "(Warning) Falha ao configurar firewall com PowerShell. Tentando fallback com netsh..."
        try {
            netsh advfirewall firewall add rule name="RDP-${Port}-TCP" dir=in action=allow protocol=TCP localport=$Port 2>$null
            netsh advfirewall firewall add rule name="RDP-${Port}-UDP" dir=in action=allow protocol=UDP localport=$Port 2>$null
            Write-Host "(Success) Regras de firewall aplicadas via netsh (fallback)."
            return $true
        } catch {
            Write-Host "(Error) Erro crÃ­tico ao configurar firewall. Erro: $($_.Exception.Message)"
            return $false
        }
    }
} # Fim da funÃ§Ã£o Configure-Firewall


# FunÃ§Ã£o para configurar polÃ­ticas de privacidade e Defender
function Configure-DefenderAndPrivacy {
    try {
        Write-Host "(Info) Aplicando polÃ­ticas de privacidade restantes e Windows Defender..."

        # ConfiguraÃ§Ãµes do Windows Defender
        try {
            Set-MpPreference -DisableAutoExclusions $true -ErrorAction SilentlyContinue
            Set-MpPreference -SubmitSamplesConsent 0 -ErrorAction SilentlyContinue
            Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue
            Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Write-Host "(Success) ConfiguraÃ§Ãµes do Windows Defender aplicadas."
        } catch {
            Write-Host "(Warning) Falha ao configurar o Windows Defender. Erro: $($_.Exception.Message)"
        }

        # PolÃ­ticas de Windows Update
        try {
            $wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            if (-not (Test-Path $wuPolicyPath)) { New-Item -Path $wuPolicyPath -Force | Out-Null }
            $wuAUPath = Join-Path $wuPolicyPath "AU"
            if (-not (Test-Path $wuAUPath)) { New-Item -Path $wuAUPath -Force | Out-Null }

            New-ItemProperty -Path $wuPolicyPath -Name "WUServer" -Value "http://127.0.0.1" -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $wuPolicyPath -Name "WUStatusServer" -Value "http://127.0.0.1" -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $wuAUPath -Name "UseWUServer" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $wuPolicyPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host "(Success) Ajustes de Windows Update aplicados (direcionamento para loopback)."
        } catch {
            Write-Host "(Warning) Falha ao aplicar ajustes de Windows Update. Erro: $($_.Exception.Message)"
        }
        
        # Instalar PSWindowsUpdate (se nÃ£o existir)
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Host "(Info) Instalando mÃ³dulo PSWindowsUpdate..."
            try {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
                Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
                Write-Host "(Success) MÃ³dulo PSWindowsUpdate instalado."
            } catch {
                Write-Host "(Warning) Falha ao instalar PSWindowsUpdate. Erro: $($_.Exception.Message)"
            }
        }

        Write-Host "(Success) PolÃ­ticas de privacidade e Windows Defender configuradas."
        return $true
    } catch {
        Write-Host "(Error) Erro na funÃ§Ã£o Configure-DefenderAndPrivacy: $($_.Exception.Message)"
        return $false
    }
} # Fim da funÃ§Ã£o Configure-DefenderAndPrivacy





function Main {
    try {
        Write-Host "[Info] Starting RDP multi-session + stealth setup..."

        $osInfo = Get-OSInfo
        $osVersion = Get-OSVersion

        if ($osInfo) {
            Write-Host "[Info] OS detected: $osVersion ($($osInfo.FullOSBuild)) - $($osInfo.Architecture)"
        } else {
            Write-Host "[Info] OS detected: $osVersion (basic mode)"
        }

        if (Get-Command -Name Configure-StealthMode -ErrorAction SilentlyContinue) {
            & Configure-StealthMode
            Write-Host "[Info] Configure-StealthMode executed."
        } else {
            Write-Host "[Warn] Configure-StealthMode not found; skipping."
        }
      
        if (Get-Command -Name Add-RDPUserAccount -ErrorAction SilentlyContinue) {
            & Add-RDPUserAccount -userName $RDPUserName -userPassword $RDPUserPassword
            Write-Host "[Info] Add-RDPUserAccount executed."
        } else {
            Write-Host "[Warn] Add-RDPUserAccount not found; skipping."
        }

        if (Get-Command -Name Enable-RemoteDesktop -ErrorAction SilentlyContinue) {
            & Enable-RemoteDesktop -Port $RDPPort
            Write-Host "[Info] Enable-RemoteDesktop executed."
        } else {
            Write-Host "[Warn] Enable-RemoteDesktop not found; skipping."
        }

        if (Get-Command -Name Set-UACConfiguration -ErrorAction SilentlyContinue) {
            & Set-UACConfiguration
            Write-Host "[Info] Set-UACConfiguration executed."
        } else {
            Write-Host "[Warn] Set-UACConfiguration not found; skipping."
        }

        if (Get-Command -Name Fix-RDPAccountRestrictions -ErrorAction SilentlyContinue) {
            & Fix-RDPAccountRestrictions
            Write-Host "[Info] Fix-RDPAccountRestrictions executed."
        } else {
            Write-Host "[Warn] Fix-RDPAccountRestrictions not found; skipping."
        }

        if (Get-Command -Name Configure-Firewall -ErrorAction SilentlyContinue) {
            & Configure-Firewall -Port $RDPPort
            Write-Host "[Info] Configure-Firewall executed."
        } else {
            Write-Host "[Warn] Configure-Firewall not found; skipping."
        }

        # 4) Termsrv.dll processing
        Write-Host "[Info] Processing termsrv.dll for multi-session patch..."

        $termsrvDllFile = Join-Path $env:SystemRoot "System32\termsrv.dll"
        $termsrvDllCopy = Join-Path $env:SystemRoot "System32\termsrv.dll.copy"
        $termsrvPatched = Join-Path $env:SystemRoot "System32\termsrv.dll.patched"

        if (-not (Test-Path -Path $termsrvDllFile -PathType Leaf)) {
            Write-Host "[Error] termsrv.dll not found at $termsrvDllFile. Aborting patch step."
        } else {
            $termsrvDllAcl = $null
            try {
                # backup registry (best-effort)
                try {
                    $backupDate = Get-Date -Format "yyyyMMdd_HHmmss"
                    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "$env:TEMP\rdp_config_backup_$backupDate.reg" /y > $null 2>&1
                    Write-Host "[Info] RDP registry backup exported."
                } catch {
                    Write-Host "[Warn] Could not export RDP registry: $($_.Exception.Message)"
                }

                # stop RDP related services
                $null = Stop-TermService

                # save ACL
                try {
                    $termsrvDllAcl = Get-Acl -Path $termsrvDllFile
                } catch {
                    Write-Host "[Warn] Could not read ACL for termsrv.dll: $($_.Exception.Message)"
                }

                # optional file backup
                if (-not $NoBackup) {
                    try {
                        Copy-Item -Path $termsrvDllFile -Destination $termsrvDllCopy -Force -ErrorAction Stop
                        Write-Host "[Info] Backup of termsrv.dll created at $termsrvDllCopy"
                    } catch {
                        Write-Host "[Warn] Could not copy termsrv.dll to backup: $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "[Info] NoBackup flag set; skipping physical backup."
                }

                # take ownership and grant current user full control (best-effort)
                try {
                    takeown.exe /F $termsrvDllFile > $null 2>&1
                    $currentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    icacls.exe $termsrvDllFile /grant "$($currentUserName):F" > $null 2>&1
                    Write-Host "[Info] Took ownership/granted permissions to current user."
                } catch {
                    Write-Host "[Warn] Could not change ownership/permissions: $($_.Exception.Message)"
                }

                # read file bytes and convert to hex text
                try {
                    $dllAsByte = [System.IO.File]::ReadAllBytes($termsrvDllFile)
                    $dllAsText = ($dllAsByte | ForEach-Object { $_.ToString('X2') }) -join ' '
                    Write-Host "[Info] termsrv.dll read into memory."
                } catch {
                    throw "Failed to read termsrv.dll: $($_.Exception.Message)"
                }

                $termsrvVersionInfo = Get-TermsrvDllVersionInfo -FilePath $termsrvDllFile
                if ($termsrvVersionInfo) {
                    Write-Host "[Info] termsrv.dll version detectado: $($termsrvVersionInfo.VersionText)"
                } else {
                    Write-Host "[Warn] Nao foi possivel identificar a versao do termsrv.dll."
                }

                $rdpWrapIniData = Get-RdpWrapConfiguration

                # -----------------------------------------------------------
                # INJEÃ‡ÃƒO MANUAL DE DADOS (10.0.26100.7309)
                # -----------------------------------------------------------
                if ($termsrvVersionInfo.VersionText -eq "10.0.26100.7309") {
                    Write-Host "[Info] >> INJETANDO DEFINIÃ‡ÃƒO MANUAL PARA 10.0.26100.7309 <<" -ForegroundColor Cyan
                    
                    # Definimos os cÃ³digos hexadecimais (PatchCodes) e a seÃ§Ã£o da versÃ£o
                    $customIniContent = @"
[PatchCodes]
mov_eax_1_nop_2=B8010000009090
CDefPolicy_Query_eax_rcx_jmp=B80001000089813806000090EB
jmpshort=EB
nop=90

[10.0.26100.7309]
SingleUserPatch.x64=1
SingleUserOffset.x64=9F04B
SingleUserCode.x64=mov_eax_1_nop_2
DefPolicyPatch.x64=1
DefPolicyOffset.x64=9C46F
DefPolicyCode.x64=CDefPolicy_Query_eax_rcx_jmp
LocalOnlyPatch.x64=1
LocalOnlyOffset.x64=923E1
LocalOnlyCode.x64=jmpshort
"@
                    $customData = Convert-RdpWrapIniToHashtable -IniContent $customIniContent

                    # Inicializa hashtable se o download falhou
                    if (-not $rdpWrapIniData) { $rdpWrapIniData = @{} }
                    
                    # Mescla PatchCodes (necessÃ¡rio para traduzir 'mov_eax_1_nop_2' para bytes)
                    if (-not $rdpWrapIniData.ContainsKey('PatchCodes')) { $rdpWrapIniData['PatchCodes'] = @{} }
                    foreach($k in $customData['PatchCodes'].Keys) { 
                        $rdpWrapIniData['PatchCodes'][$k] = $customData['PatchCodes'][$k] 
                    }
                    
                    # Adiciona a seÃ§Ã£o da versÃ£o especÃ­fica
                    $rdpWrapIniData['10.0.26100.7309'] = $customData['10.0.26100.7309']
                }
                # -----------------------------------------------------------

                $rdpWrapPatchPlan = $null
                $archKey = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }

                if ($termsrvVersionInfo) {
                    if ($rdpWrapIniData) {
                        $rdpWrapPatchPlan = Get-RdpWrapPatchPlan -IniData $rdpWrapIniData -VersionText $termsrvVersionInfo.VersionText -ArchitectureKey $archKey
                        if ($rdpWrapPatchPlan) {
                            Write-Host "[Info] Entrada '$($rdpWrapPatchPlan.Version)' encontrada ($archKey)."
                        } else {
                            Write-Host "[Warn] Sem correspondencia no rdpwrap.ini para versao $($termsrvVersionInfo.VersionText) ($archKey)."
                        }
                    }
                }

                # set up common patterns (used as fallback)
                $patterns = @{
                    Standard = [regex]'39 81 3C 06 00 00 0F (?:[0-9A-F]{2} ){4}00'
                    Win24H2  = [regex]'8B 81 38 06 00 00 39 81 3C 06 00 00 75'
                    Win7_Pattern1 = [regex]'8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 2F C3 00 00'
                    Win7_Pattern2 = [regex]'4C 24 60 BB 01 00 00 00'
                    Win7_Pattern3 = [regex]'83 7C 24 50 00 74 18 48 8D'
                    Win7_Pattern4 = [regex]'8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00'
                    Win7_Pattern5 = [regex]'83 7C 24 50 00 74 43 48 8D'
                }

                $patchApplied = $false

                if ($rdpWrapPatchPlan -and $rdpWrapPatchPlan.Entries.Count -gt 0) {
                    Write-Host "[Info] Aplicando offsets dinamicos..."
                    $patchPlanEntries = $rdpWrapPatchPlan.Entries

                    $dynamicPatchScript = {
                        param(
                            [string]$DllAsText,
                            [byte[]]$DllBytes,
                            [object[]]$PatchEntries
                        )

                        if (-not $DllBytes) { throw "Patch dinamico requer bytes do arquivo original." }
                        if (-not $PatchEntries) { throw "Nenhuma entrada de patch dinamico fornecida." }

                        $bytesCopy = New-Object byte[] ($DllBytes.Length)
                        [System.Buffer]::BlockCopy($DllBytes, 0, $bytesCopy, 0, $DllBytes.Length)

                        foreach ($entry in $PatchEntries) {
                            $offset = [int]$entry.Offset
                            if (($offset + $entry.Bytes.Length) -gt $bytesCopy.Length) {
                                throw "Patch '$($entry.Name)' excede o tamanho do arquivo (offset $offset)."
                            }
                            [System.Buffer]::BlockCopy($entry.Bytes, 0, $bytesCopy, $offset, $entry.Bytes.Length)
                        }

                        return ($bytesCopy | ForEach-Object { $_.ToString('X2') }) -join ' '
                    }

                    $dynamicPatchParams = @{
                        DllBytes     = $dllAsByte
                        PatchEntries = $patchPlanEntries
                    }

                    $patchApplied = Update-TermsrvDll -TermsrvDllAsFile $termsrvDllFile `
                                                      -TermsrvDllAsPatch $termsrvPatched `
                                                      -TermsrvDllAsText $dllAsText `
                                                      -TermsrvAclObject $termsrvDllAcl `
                                                      -PatchLogic $dynamicPatchScript `
                                                      -PatchParams $dynamicPatchParams
                }

                if (-not $patchApplied) {
                    # Fallback para regex
                    switch ($osVersion) {
                    'Windows 7' {
                        $osBuild = if ($osInfo) { $osInfo.FullOSBuild } else { "(unknown)" }
                        Write-Host "[Info] Windows 7 detected. Build: $osBuild"

                        $dllAsTextReplacedForWin7 = $dllAsText

                        if ($osBuild -eq '7601.23964' -and $osInfo.Architecture -eq '64-bit') {
                            $dllAsTextReplacedForWin7 = $dllAsTextReplacedForWin7 `
                                -replace $patterns.Win7_Pattern1, 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                                -replace $patterns.Win7_Pattern2, '4C 24 60 BB 00 00 00 00' `
                                -replace $patterns.Win7_Pattern3, '83 7C 24 50 00 EB 18 48 8D'
                        } elseif ($osInfo.Architecture -eq '64-bit') {
                            $dllAsTextReplacedForWin7 = $dllAsTextReplacedForWin7 `
                                -replace $patterns.Win7_Pattern4, 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                                -replace $patterns.Win7_Pattern2, '4C 24 60 BB 00 00 00 00' `
                                -replace $patterns.Win7_Pattern5, '83 7C 24 50 00 EB 18 48 8D'
                        } else {
                            Write-Host "[Warn] Windows 7 build or architecture not supported for automated patch."
                        }

                        $scriptBlockForWin7Patch = {
                            param($DllAsText)
                            return $dllAsTextReplacedForWin7
                        }

                        $patchApplied = Update-TermsrvDll -TermsrvDllAsFile $termsrvDllFile `
                                                          -TermsrvDllAsPatch $termsrvPatched `
                                                          -TermsrvDllAsText $dllAsText `
                                                          -TermsrvAclObject $termsrvDllAcl `
                                                          -PatchLogic $scriptBlockForWin7Patch
                    }

                    'Windows 11' {
                        if ($osInfo -and $osInfo.DisplayVersion -eq '24H2') {
                            $patchApplied = Update-TermsrvDll -TermsrvDllAsFile $termsrvDllFile -TermsrvDllAsPatch $termsrvPatched -TermsrvDllAsText $dllAsText -TermsrvAclObject $termsrvDllAcl -PatchLogic { param($DllAsText) $DllAsText -replace $patterns.Win24H2, 'B8 00 01 00 00 89 81 38 06 00 00 90 EB' }
                        } else {
                            $patchApplied = Update-TermsrvDll -TermsrvDllAsFile $termsrvDllFile -TermsrvDllAsPatch $termsrvPatched -TermsrvDllAsText $dllAsText -TermsrvAclObject $termsrvDllAcl -PatchLogic { param($DllAsText) $DllAsText -replace $patterns.Standard, 'B8 00 01 00 00 89 81 38 06 00 00 90' }
                        }
                    }

                    'Windows 10' {
                        $patchApplied = Update-TermsrvDll -TermsrvDllAsFile $termsrvDllFile -TermsrvDllAsPatch $termsrvPatched -TermsrvDllAsText $dllAsText -TermsrvAclObject $termsrvDllAcl -PatchLogic { param($DllAsText) $DllAsText -replace $patterns.Standard, 'B8 00 01 00 00 89 81 38 06 00 00 90' }
                    }

                    'Windows Server 2016/2019' {
                        $patchApplied = Update-TermsrvDll -TermsrvDllAsFile $termsrvDllFile -TermsrvDllAsPatch $termsrvPatched -TermsrvDllAsText $dllAsText -TermsrvAclObject $termsrvDllAcl -PatchLogic { param($DllAsText) $DllAsText -replace $patterns.Standard, 'B8 00 01 00 00 89 81 38 06 00 00 90' }
                    }

                    'Windows Server 2022' {
                        $patchApplied = Update-TermsrvDll -TermsrvDllAsFile $termsrvDllFile -TermsrvDllAsPatch $termsrvPatched -TermsrvDllAsText $dllAsText -TermsrvAclObject $termsrvDllAcl -PatchLogic { param($DllAsText) $DllAsText -replace $patterns.Standard, 'B8 00 01 00 00 89 81 38 06 00 00 90' }
                    }

                    Default {
                        Write-Host "[Warn] No specific patch for $osVersion, trying generic..."
                        $patchApplied = Update-TermsrvDll -TermsrvDllAsFile $termsrvDllFile -TermsrvDllAsPatch $termsrvPatched -TermsrvDllAsText $dllAsText -TermsrvAclObject $termsrvDllAcl -PatchLogic { param($DllAsText) $DllAsText -replace $patterns.Standard, 'B8 00 01 00 00 89 81 38 06 00 00 90' }
                    }
                }
                }

                if (-not $patchApplied) {
                    Write-Host "[Warn] Patch was not applied for this OS/version."
                } else {
                    Write-Host "[Success] Patch process finished (attempted)."
                }

            } catch {
                Write-Host "[Error] Critical error during termsrv.dll patch: $($_.Exception.Message)"
                if ($termsrvDllAcl) {
                    try { Set-Acl -Path $termsrvDllFile -AclObject $termsrvDllAcl -ErrorAction SilentlyContinue } catch {}
                }
            }
        }

        Write-Host "[Info] Process finished. Reboot may be required."

    } catch {
        Write-Host "[Error] Critical error in Main: $($_.Exception.Message)"
    }
}

 Main
