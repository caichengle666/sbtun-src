<#
.SYNOPSIS
  在 Windows 上启动真实的 sing-box TUN（Wintun + gVisor 栈），并在同一个进程里检测网卡和地址。

.DESCRIPTION
  GitHub Actions 的 Windows runner 会在每个 step 结束时结束该 step 启动的整个进程树，
  所以 sing-box 必须在“启动”的同一个 step 里完成检测，不能留到下一个 step 再检查。
  （之前的工作流在一个 step 里 Start-Process，到下一个 step 时进程已经被 runner 结束，
  检测循环第一次就是 process=False。）

  通过条件（全部满足才算通过，任何一项不满足都会失败）：
    1. sing-box 进程在整个检测期间一直存活；
    2. 出现名为 $InterfaceName 的网卡，且状态为 Up；
    3. 172.19.0.1 地址绑定在这块网卡上（按 ifIndex 校验，不是随便哪块网卡）；
    4. 网卡就绪后再观察 $StableSeconds 秒，进程仍然存活、地址仍然在。

  失败时打印：sing-box stdout/stderr、sbtun 日志（如果有）、Get-NetAdapter、
  Get-NetIPAddress、route print、Wintun 相关的 PnP 设备。
#>
[CmdletBinding()]
param(
    [string]$SingBox = $env:SINGBOX,
    [string]$WorkDir = $(if ($env:RUNNER_TEMP) { Join-Path $env:RUNNER_TEMP 'sbtun-tun-test' } else { Join-Path ([IO.Path]::GetTempPath()) 'sbtun-tun-test' }),
    [string]$InterfaceName = 'sbtun-ci',
    [string]$Address = '172.19.0.1',
    [int]$PrefixLength = 30,
    [int]$TimeoutSeconds = 30,
    [int]$StableSeconds = 3,
    # sbtun 自己的日志目录（可选）。本测试只直接启动 sing-box，没有 sbtun 进程；
    # 如果以后改成通过 sbtun 启动，把它的数据目录传进来，失败时会一并打印。
    [string]$SbtunLogDir = $env:SBTUN_LOG_DIR
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Section([string]$title) {
    Write-Host ''
    Write-Host "===== $title ====="
}

function Show-File([string]$path) {
    Write-Section $path
    if (Test-Path -LiteralPath $path) {
        $content = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrEmpty($content)) { Write-Host '(文件为空)' } else { Write-Host $content }
    } else {
        Write-Host '(文件不存在)'
    }
}

function Show-Diagnostics {
    param([System.Diagnostics.Process]$Process, [string]$StdOut, [string]$StdErr)

    Write-Section 'sing-box 进程'
    if ($Process) {
        $Process.Refresh()
        if ($Process.HasExited) {
            Write-Host "已退出，ExitCode=$($Process.ExitCode)，退出时间=$($Process.ExitTime)"
        } else {
            Write-Host "仍在运行，PID=$($Process.Id)"
        }
    } else {
        Write-Host '(没有进程对象)'
    }

    # sing-box 的日志写到 stderr，stdout 一般是空的；两个都打印。
    Show-File $StdOut
    Show-File $StdErr

    Write-Section 'sbtun 日志'
    if ($SbtunLogDir -and (Test-Path -LiteralPath $SbtunLogDir)) {
        $logs = @(Get-ChildItem -LiteralPath $SbtunLogDir -Filter '*.log' -Recurse -ErrorAction SilentlyContinue)
        if ($logs.Count -eq 0) { Write-Host "($SbtunLogDir 下没有 .log 文件)" }
        foreach ($log in $logs) { Show-File $log.FullName }
    } else {
        Write-Host '(本测试直接启动 sing-box，没有 sbtun 进程；未设置 SBTUN_LOG_DIR 或目录不存在)'
    }

    Write-Section 'Get-NetAdapter -IncludeHidden'
    Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Format-Table -AutoSize Name, InterfaceDescription, ifIndex, Status, MediaConnectionState |
        Out-String -Width 300 | Write-Host

    Write-Section 'Get-NetIPAddress'
    Get-NetIPAddress -ErrorAction SilentlyContinue |
        Format-Table -AutoSize ifIndex, InterfaceAlias, IPAddress, PrefixLength, PrefixOrigin, AddressState |
        Out-String -Width 300 | Write-Host

    Write-Section 'route print'
    & route.exe print | Out-String -Width 300 | Write-Host

    Write-Section 'Wintun PnP 设备'
    Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -match 'Wintun|sing|sbtun' -or $_.InstanceId -match 'WINTUN' } |
        Format-Table -AutoSize Status, FriendlyName, InstanceId |
        Out-String -Width 300 | Write-Host
}

if (-not $SingBox -or -not (Test-Path -LiteralPath $SingBox)) {
    throw "找不到 sing-box.exe：'$SingBox'（请设置 SINGBOX 环境变量或 -SingBox 参数）"
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$configPath = Join-Path $WorkDir 'config.json'
$stdOut = Join-Path $WorkDir 'sing-box.stdout.log'
$stdErr = Join-Path $WorkDir 'sing-box.stderr.log'
Remove-Item -LiteralPath $stdOut, $stdErr -Force -ErrorAction SilentlyContinue

$config = [ordered]@{
    log       = [ordered]@{ level = 'trace'; timestamp = $true }
    inbounds  = @(
        [ordered]@{
            type           = 'tun'
            tag            = 'tun-test'
            interface_name = $InterfaceName
            address        = @("$Address/$PrefixLength")
            auto_route     = $false
            strict_route   = $false
            stack          = 'gvisor'
        }
    )
    outbounds = @([ordered]@{ type = 'direct'; tag = 'direct' })
    route     = [ordered]@{ auto_detect_interface = $true; final = 'direct' }
}
$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $configPath -Encoding utf8
Write-Host "配置文件：$configPath"
Get-Content -LiteralPath $configPath | Write-Host

& $SingBox check -c $configPath
if ($LASTEXITCODE -ne 0) { throw "sing-box check 失败，退出码 $LASTEXITCODE" }

# 同名网卡残留会让 sing-box 复用或失败，先确认环境干净（只打印，不清理别人的网卡）。
$stale = @(Get-NetAdapter -IncludeHidden -Name $InterfaceName -ErrorAction SilentlyContinue)
if ($stale.Count -gt 0) { Write-Host "注意：启动前已存在同名网卡 $InterfaceName（状态 $($stale[0].Status)）" }

$proc = $null
$passed = $false
$failure = $null
try {
    $proc = Start-Process -FilePath $SingBox `
        -ArgumentList @('run', '-c', "`"$configPath`"") `
        -WorkingDirectory (Split-Path -Parent $SingBox) `
        -RedirectStandardOutput $stdOut `
        -RedirectStandardError $stdErr `
        -NoNewWindow -PassThru
    $null = $proc.Handle  # 缓存句柄，进程退出后才能读到 ExitCode
    Write-Host "sing-box 已启动，PID=$($proc.Id)，Wintun=$env:WINTUN_VERSION，网卡名=$InterfaceName"

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        $attempt++
        $proc.Refresh()
        $alive = -not $proc.HasExited
        $adapter = Get-NetAdapter -IncludeHidden -Name $InterfaceName -ErrorAction SilentlyContinue | Select-Object -First 1
        $ip = $null
        if ($adapter) {
            $ip = Get-NetIPAddress -IPAddress $Address -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        $adapterText = if ($adapter) { "$($adapter.Name)/$($adapter.InterfaceDescription)/ifIndex=$($adapter.ifIndex)/$($adapter.Status)" } else { '无' }
        $ipText = if ($ip) { "$($ip.IPAddress)/$($ip.PrefixLength) $($ip.AddressState)" } else { '无' }
        Write-Host "检测 ${attempt}: process=$alive adapter=$adapterText address=$ipText"

        if (-not $alive) {
            $failure = "sing-box 进程已退出（ExitCode=$($proc.ExitCode)），TUN 未就绪"
            break
        }
        if ($adapter -and $adapter.Status -eq 'Up' -and $ip) {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 1
    }

    if ($ready) {
        # 就绪后再观察一会儿，确认不是一闪而过。
        Start-Sleep -Seconds $StableSeconds
        $proc.Refresh()
        $adapter = Get-NetAdapter -IncludeHidden -Name $InterfaceName -ErrorAction SilentlyContinue | Select-Object -First 1
        $ip = if ($adapter) { Get-NetIPAddress -IPAddress $Address -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1 } else { $null }
        if ($proc.HasExited) {
            $failure = "TUN 就绪后 sing-box 在 $StableSeconds 秒内退出（ExitCode=$($proc.ExitCode)）"
        } elseif (-not $adapter -or -not $ip) {
            $failure = "TUN 就绪后 $StableSeconds 秒内网卡或地址消失"
        } else {
            $passed = $true
        }
    } elseif (-not $failure) {
        $failure = "等待 $TimeoutSeconds 秒后仍未找到 Up 状态的网卡 $InterfaceName 及其上的地址 $Address"
    }
} catch {
    $failure = "测试脚本异常：$($_.Exception.Message)"
} finally {
    if (-not $passed) {
        Show-Diagnostics -Process $proc -StdOut $stdOut -StdErr $stdErr
    }
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        $null = $proc.WaitForExit(5000)
    }
}

if (-not $passed) {
    Write-Host "::error title=Windows TUN 测试失败::$failure"
    throw "真实 TUN 后端未正确初始化：$failure"
}

Write-Section 'sing-box 日志（通过）'
Show-File $stdErr
Write-Host "真实 TUN 后端初始化成功：网卡 $InterfaceName 已 Up，地址 $Address/$PrefixLength 已绑定，sing-box 运行正常。"
