param([string]$OutputRoot = '', [switch]$WindowsSmoke)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Build and package on Windows.' }
$repo = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $repo
$utf8 = New-Object System.Text.UTF8Encoding($false)
function Write-Utf8([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, $utf8) }
function Run-Go([string[]]$GoArguments) { & go @GoArguments; if ($LASTEXITCODE -ne 0) { throw "Go command failed: $($GoArguments -join ' ')" } }
function Ensure-Directory([string]$Path) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
function Fetch([string]$Url, [string]$Path, [string]$Hash = '') {
    if (-not (Test-Path -LiteralPath $Path)) {
        Ensure-Directory (Split-Path $Path -Parent)
        & curl.exe --fail --location --silent --show-error --retry 3 --max-time 180 --output "$Path.partial" $Url
        if ($LASTEXITCODE -ne 0) { throw "Download failed: $Url" }
        Move-Item -LiteralPath "$Path.partial" -Destination $Path
    }
    if ($Hash -and (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -ne $Hash) { throw "Checksum mismatch: $Url" }
}
function Engine-LicenseModules([string]$Binary) {
    $rows=@(& go version -m $Binary)
    $pending=$null
    foreach($row in $rows) {
        $p=$row.Trim() -split '\s+'
        if($p[0] -eq 'dep') {
            if($pending){$pending}
            $pending=@($p[1],$p[2]) -join '|'
        } elseif($p[0] -eq '=>') { $pending=@($p[1],$p[2]) -join '|' }
    }
    if($pending){$pending}
}
$goVersion = (& go env GOVERSION).Trim()
$expected = [regex]::Match((Get-Content -Raw go.mod), '(?m)^go (\d+\.\d+\.\d+)').Groups[1].Value
if ($goVersion -ne "go$expected") { throw 'Use the exact toolchain in go.mod.' }
$sourceCommit = (& git rev-parse HEAD).Trim()
function Source-Inventory {
    & git ls-files --cached --others --exclude-standard | Sort-Object | ForEach-Object { if(Test-Path -LiteralPath $_ -PathType Leaf) { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_ } }
}
$sourceInventory=@(Source-Inventory)
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
if (-not $OutputRoot) { $OutputRoot = Join-Path $repo "out/benchmark-$stamp" }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) { throw 'Output must be new: never overwrite accepted candidates.' }
Ensure-Directory $OutputRoot
$cache = Join-Path $repo 'out/benchmark-cache'
Ensure-Directory $cache
$savedEnv = @{}
foreach ($name in @('GOOS','GOARCH','GOAMD64','CGO_ENABLED','GOFLAGS')) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    $env:CGO_ENABLED='0'; $env:GOFLAGS='-mod=readonly'; $env:GOAMD64='v1'
    $env:GOOS='windows'; $env:GOARCH='amd64'
    if ($WindowsSmoke) {
        $bin = Join-Path $OutputRoot 'bin'; Ensure-Directory $bin
        Run-Go @('build','-trimpath','-o',"$bin/caddy.exe",'./cmd/caddy')
        Run-Go @('build','-trimpath','-o',"$bin/stock-caddy.exe",'./benchmarks/stockcaddy')
        Run-Go @('build','-trimpath','-o',"$bin/appsec-bench.exe",'./benchmarks/runner')
        $smokeSums=@(Get-ChildItem -LiteralPath $bin -File | Sort-Object Name | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  bin/'+$_.Name })
        Write-Utf8 "$OutputRoot/SHA256SUMS" (($smokeSums -join "`n")+"`n")
        Write-Output "windows_smoke_bundle=$OutputRoot"
        return
    }
    # Go's ./... traversal ignores underscore-prefixed staging directories.
    $stage = Join-Path $OutputRoot '_bundle'; Ensure-Directory $stage
    $bin = Join-Path $stage 'bin'; Ensure-Directory $bin
    $env:GOOS='linux'; $env:GOARCH='amd64'
    foreach ($target in @(@('caddy','./cmd/caddy'),@('stock-caddy','./benchmarks/stockcaddy'),@('appsec-bench','./benchmarks/runner'))) {
        Run-Go @('build','-trimpath','-o',"$bin/$($target[0])",$target[1])
    }
    Run-Go @('test','-c','-trimpath','-o',"$bin/appsec-microbench",'./modules/appsec')
    Run-Go @('build','-trimpath','-o',"$OutputRoot/artifact-server",'./cmd/artifact-server')
    $pins = Get-Content -Raw modules/appsec/profiles/pins.json | ConvertFrom-Json
    $releaseHash='6e0b2add0ff3231dca3db7146834d7fea028215b915e2da39ebe30fc9f11436f'
    $release = Join-Path $cache 'crowdsec-v1.8.2.tgz'
    $previousDownload = Join-Path $env:TEMP 'trueops-bench-crowdsec-v1.8.2.tgz'
    if (-not (Test-Path $release) -and (Test-Path $previousDownload) -and (Get-FileHash $previousDownload -Algorithm SHA256).Hash.ToLowerInvariant() -eq $releaseHash) { Copy-Item -LiteralPath $previousDownload -Destination $release }
    Fetch 'https://github.com/crowdsecurity/crowdsec/releases/download/v1.8.2/crowdsec-release.tgz' $release $releaseHash
    $unpack = Join-Path $cache 'engine-release'
    if (-not (Test-Path "$unpack/crowdsec-v1.8.2/cmd/crowdsec/crowdsec")) {
        Ensure-Directory $unpack
        & tar -xzf $release -C $unpack 'crowdsec-v1.8.2/cmd/crowdsec/crowdsec' 'crowdsec-v1.8.2/cmd/crowdsec-cli/cscli'
        if ($LASTEXITCODE -ne 0) { throw 'Engine extraction failed.' }
    }
    $engineBin=Join-Path $stage 'engine'; Ensure-Directory $engineBin
    Copy-Item -LiteralPath "$unpack/crowdsec-v1.8.2/cmd/crowdsec/crowdsec","$unpack/crowdsec-v1.8.2/cmd/crowdsec-cli/cscli" -Destination $engineBin
    $template=Join-Path $stage 'engine-template'; Ensure-Directory $template
    foreach ($d in @('appsec-configs','appsec-rules','data','data/schemas','hub','notifications','plugins','parsers','scenarios','postoverflows','contexts','collections','patterns')) { Ensure-Directory "$template/$d" }
    Write-Utf8 "$template/hub/.index.json" '{}'
    Write-Utf8 "$template/simulation.yaml" "simulation: false`n"
    Copy-Item -LiteralPath modules/appsec/profiles/no-firewall-decisions.yaml -Destination "$template/profiles.yaml"
    # Download immutable Hub objects concurrently, then check every reviewed hash.
    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    try {
        $jobs=@()
        foreach ($asset in $pins.hub_assets) {
            $path=Join-Path $cache $asset.path
            Ensure-Directory (Split-Path $path -Parent)
            if (-not (Test-Path -LiteralPath $path)) { $jobs += [pscustomobject]@{Path=$path; Task=$client.GetByteArrayAsync("https://raw.githubusercontent.com/crowdsecurity/hub/$($pins.hub.commit)/$($asset.path)")} }
        }
        foreach ($job in $jobs) { [IO.File]::WriteAllBytes($job.Path,$job.Task.GetAwaiter().GetResult()) }
    } finally { $client.Dispose() }
    foreach ($asset in $pins.hub_assets) {
        $path=Join-Path $cache $asset.path
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ne $asset.sha256) { throw "Hub hash mismatch: $($asset.path)" }
        Copy-Item -LiteralPath $path -Destination "$template/$($asset.kind)/$([IO.Path]::GetFileName($asset.path))"
    }
    Copy-Item -LiteralPath modules/appsec/profiles/native-waf.yaml,modules/appsec/profiles/native-features.yaml -Destination "$template/appsec-configs"
    Copy-Item -LiteralPath modules/appsec/profiles/crs.yaml -Destination "$template/appsec-rules/trueops-crs.yaml"
    Copy-Item -LiteralPath modules/appsec/profiles/schemas/example-api.yaml -Destination "$template/data/schemas"
    $crsZip=Join-Path $cache 'coreruleset-4.30.0-minimal.zip'
    $previousCRS=Join-Path $env:TEMP 'coreruleset-4.30.0-minimal.zip'
    if (-not (Test-Path $crsZip) -and (Test-Path $previousCRS)) { Copy-Item -LiteralPath $previousCRS -Destination $crsZip }
    Fetch $pins.crs.archive $crsZip $pins.crs.sha256
    # Preserve the verified upstream archive. The Windows-built runner extracts
    # it only into its private VPS data directory; do not mutate/filter rules.
    Copy-Item -LiteralPath $crsZip -Destination "$stage/coreruleset-4.30.0-minimal.zip"
    Copy-Item -LiteralPath LICENSE -Destination $stage
    Copy-Item -LiteralPath modules/appsec/profiles/pins.json -Destination "$stage/profile-pins.json"
    Copy-Item -LiteralPath benchmarks/README.md -Destination "$stage/README.md"
    Write-Utf8 "$stage/run.sh" (([IO.File]::ReadAllText("$repo/benchmarks/run.sh")).Replace("`r`n","`n"))
    $licenses=Join-Path $stage 'licenses'; Ensure-Directory $licenses
    Copy-Item -LiteralPath ((& go env GOROOT).Trim()+'/LICENSE') -Destination "$licenses/GO-LICENSE"
    $moduleLines=@(& go list -deps -f '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}' ./cmd/caddy ./benchmarks/stockcaddy ./benchmarks/runner ./cmd/artifact-server | Where-Object {$_} | Sort-Object -Unique)
    if ($LASTEXITCODE -ne 0) { throw 'Dependency inventory failed.' }
    $goExe=Join-Path ((& go env GOROOT).Trim()) 'bin/go.exe'
    foreach($engineModule in @(Engine-LicenseModules "$engineBin/crowdsec"; Engine-LicenseModules "$engineBin/cscli") | Sort-Object -Unique) {
        $p=$engineModule.Split('|')
        if(@($moduleLines | Where-Object {$_.StartsWith($engineModule+'|')}).Count -ne 0){continue}
        # Explicit versions in an unrelated temporary working directory keep
        # redistribution-license retrieval out of this repository's Go graph.
        Push-Location -LiteralPath ([IO.Path]::GetTempPath())
        try { $download=(& $goExe mod download -json ($p[0]+'@'+$p[1])) | ConvertFrom-Json; if($LASTEXITCODE -ne 0 -or $download.Error){throw "License source unavailable: $engineModule"} }
        finally { Pop-Location }
        $moduleLines+=($engineModule+'|'+$download.Dir)
    }
    $moduleLines=@($moduleLines | Sort-Object -Unique)
    $notices=New-Object System.Collections.Generic.List[string]
    $notices.Add('TrueOps AppSec benchmark bundle. Upstream code retains its own license.'); $notices.Add('Go runtime: licenses/GO-LICENSE. Engine: official CrowdSec v1.8.2; see licenses/crowdsec. Hub: licenses/hub. CRS: coreruleset-4.30.0/LICENSE inside coreruleset-4.30.0-minimal.zip.');
    foreach ($line in $moduleLines) {
        $parts=$line.Split('|');if (-not $parts[1]) { continue }
        $dest=Join-Path $licenses ($parts[0].Replace('/','_')+'@'+$parts[1]);Ensure-Directory $dest
        $legal=@(Get-ChildItem -LiteralPath $parts[2] | Where-Object {$_.Name -match '^(licen[sc]e|notice|copying|copyright|authors)(\b|\.|-|_)' -and $_.Extension -notin @('.go','.c','.h','.cpp','.js','.py','.ts','.rs')})
        if ($legal.Count -eq 0) { throw "Review missing dependency license: $($parts[0])" }
        foreach ($file in $legal) { Copy-Item -LiteralPath $file.FullName -Destination $dest -Recurse }
        $notices.Add($parts[0]+' '+$parts[1]+' -> licenses/'+(Split-Path $dest -Leaf))
    }
    foreach ($pair in @(@('crowdsec','https://raw.githubusercontent.com/crowdsecurity/crowdsec/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/LICENSE'),@('hub','https://raw.githubusercontent.com/crowdsecurity/hub/04bf592e846e05bda8851d7665141fb69e6e08d3/LICENSE'))) { Ensure-Directory "$licenses/$($pair[0])"; Fetch $pair[1] "$licenses/$($pair[0])/LICENSE" }
    Write-Utf8 "$stage/THIRD_PARTY_NOTICES" ($notices -join "`n")
    if (($sourceInventory -join "`n") -cne (@(Source-Inventory) -join "`n")) { throw 'Source changed while packaging; do not publish this attempt. Package a fresh candidate.' }
    Write-Utf8 "$stage/source-SHA256SUMS" (($sourceInventory -join "`n")+"`n")
    $binaryInfo=@{}
    foreach($file in Get-ChildItem $bin,$engineBin -File) { $binaryInfo[$file.Name]=[ordered]@{sha256=(Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant();build_info=@(& go version -m $file.FullName)} }
    $publicModules=@($moduleLines | ForEach-Object { $m=$_.Split('|');$m[0]+' '+$m[1] })
    $manifest=[ordered]@{source_commit=$sourceCommit;source_dirty=([bool](& git status --porcelain));source_snapshot_sha256=(Get-FileHash "$stage/source-SHA256SUMS" -Algorithm SHA256).Hash.ToLowerInvariant();go_version=$goVersion;caddy_version=(& go list -m -f '{{.Version}}' github.com/caddyserver/caddy/v2).Trim();goos='linux';goarch='amd64';goamd64='v1';cgo_enabled=0;build_flags=@('-trimpath','-mod=readonly');dependency_modules=$publicModules;binaries=$binaryInfo;engine_release_archive_sha256=$releaseHash;engine_source=$pins.engine;profile_pins=$pins;acceptance='pending native VPS execution; reuse exact caddy bytes for later release'}
    Write-Utf8 "$stage/manifest.json" ($manifest | ConvertTo-Json -Depth 12)
    $sums=@(Get-ChildItem -LiteralPath $stage -File -Recurse | Sort-Object FullName | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.FullName.Substring($stage.Length+1).Replace('\','/') })
    Write-Utf8 "$stage/SHA256SUMS" (($sums -join "`n")+"`n")
    $public=Join-Path $OutputRoot 'public';Ensure-Directory $public
    $archive=Join-Path $public "trueops-appsec-benchmark-$stamp-linux-amd64.tar.gz"
    & tar -czf $archive -C $stage .
    if($LASTEXITCODE -ne 0){throw 'Archive creation failed.'}
    Write-Utf8 "$public/SHA256SUMS" ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetFileName($archive)+"`n")
    Write-Output "immutable_bundle=$OutputRoot"
    Get-Content "$public/SHA256SUMS"
} finally { foreach($name in $savedEnv.Keys){[Environment]::SetEnvironmentVariable($name,$savedEnv[$name])} }
