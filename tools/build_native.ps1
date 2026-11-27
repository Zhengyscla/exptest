$ErrorActionPreference = 'Stop'
$repo = 'C:\Users\34088\world\ghstry\work\LSPrivilege_src\LSPrivilege-main'
$ndk  = 'C:\Users\34088\world\ghstry\android-ndk-r30'
$cxx  = Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang++.cmd'

$srcs = @(
 'core/main.cpp','core/attack/ops.cpp','core/profile/entry.cpp','core/memory/address_space.cpp',
 'core/memory/heap_context.cpp','core/race/pi_race.cpp','core/route/route_controller.cpp',
 'core/route/route_middleware.cpp','core/race/threads.cpp','core/route/tcp_zerocopy_route.cpp',
 'core/route/select_stack_route.cpp','core/route/multicast_waiter_route.cpp',
 'core/memory/payload_builder.cpp','core/session/runtime_config.cpp','core/profile/binary.cpp',
 'core/support/util.cpp','core/session/exploit_session.cpp','core/session/root_child_frontend.cpp',
 'core/session/backend/cve_2026_43499_backend.cpp','core/session/handoff_probe.cpp',
 'core/session/victim_process.cpp','core/session/victim_context.cpp',
 'core/support/native_resource.cpp','core/support/run_state.cpp'
)

$out = Join-Path $repo 'build\native'
New-Item -ItemType Directory -Force $out | Out-Null
$rspDir = Join-Path $repo 'build\rsp'
New-Item -ItemType Directory -Force $rspDir | Out-Null

$common = @(
 '-O2','-Wall','-Wextra','-Wconversion','-Wsign-conversion',
 '-Wno-unused-parameter','-Wno-sign-compare','-Wno-unused-function',
 '-Icore','-DTARGET_CONFIG_H=<kernel/target.h>','-std=c++23','-fno-rtti'
)

Push-Location (Join-Path $repo 'src')
try {
    $objs = @()
    $i = 0
    foreach ($s in $srcs) {
        $o = Join-Path $out (([System.IO.Path]::GetFileNameWithoutExtension($s)) + '.o')
        $objs += $o
        $rsp = Join-Path $rspDir ("cc$i.rsp"); $i++
        $lines = $common + @('-c', ($s -replace '\\','/'), '-o', ($o -replace '\\','/'))
        Set-Content -Path $rsp -Value $lines -Encoding ascii
        Write-Host "CC $s"
        & $cxx "@$rsp"
        if ($LASTEXITCODE -ne 0) { throw "compile failed: $s" }
    }
    Write-Host 'LINK'
    $rsp = Join-Path $rspDir 'link.rsp'
    $lines = @($objs | ForEach-Object { $_ -replace '\\','/' }) +
             @('-fPIE','-pie','-pthread','-static-libstdc++','-o', ((Join-Path $out 'lsprivilege') -replace '\\','/'))
    Set-Content -Path $rsp -Value $lines -Encoding ascii
    & $cxx "@$rsp"
    if ($LASTEXITCODE -ne 0) { throw 'link failed' }
    Write-Host 'OK'
    Get-Item (Join-Path $out 'lsprivilege') | Select-Object FullName, Length
} finally {
    Pop-Location
}

