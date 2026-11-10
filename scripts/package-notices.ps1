param([Parameter(Mandatory = $true)][string]$Destination)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Push-Location -LiteralPath $repo
try {
    $moduleLines = @(& go list -deps -f '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}' ./cmd/caddy)
    if ($LASTEXITCODE -ne 0) { throw 'Release dependency inventory failed.' }
    $goRoot = (& go env GOROOT).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot locate the Go runtime license.' }

    $licenses = Join-Path $Destination 'licenses'
    New-Item -ItemType Directory -Path $licenses | Out-Null
    Copy-Item -LiteralPath (Join-Path $goRoot 'LICENSE') -Destination (Join-Path $licenses 'GO-LICENSE')
    foreach ($name in @('PATENTS', 'AUTHORS', 'CONTRIBUTORS')) {
        $path = Join-Path $goRoot $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Copy-Item -LiteralPath $path -Destination (Join-Path $licenses "GO-$name")
        }
    }

    $notices = New-Object System.Collections.Generic.List[string]
    $notices.Add((Get-Content -Raw -LiteralPath THIRD_PARTY_NOTICES).TrimEnd())
    $notices.Add('')
    $notices.Add('Go runtime -> licenses/GO-LICENSE')
    foreach ($line in @($moduleLines | Where-Object { $_ } | Sort-Object -Unique)) {
        $parts = $line.Split('|')
        if (-not $parts[1]) { continue } # The main module has its own root LICENSE.
        if (-not $parts[2]) { throw "Missing dependency source: $($parts[0])" }
        $legal = @(Get-ChildItem -LiteralPath $parts[2] | Where-Object {
            $_.Name -match '^(licen[sc]e|notice|copying|copyright|authors)(\b|\.|-|_)' -and
            $_.Extension -notin @('.go', '.c', '.h', '.cpp', '.js', '.py', '.ts', '.rs')
        })
        if ($legal.Count -eq 0) { throw "Missing dependency license: $($parts[0]) $($parts[1])" }
        $name = $parts[0].Replace('/', '_') + '@' + $parts[1]
        $target = Join-Path $licenses $name
        New-Item -ItemType Directory -Path $target | Out-Null
        foreach ($file in $legal) {
            Copy-Item -LiteralPath $file.FullName -Destination $target -Recurse
        }
        $notices.Add("$($parts[0]) $($parts[1]) -> licenses/$name")
    }
    Copy-Item -LiteralPath LICENSE -Destination $Destination
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $Destination 'THIRD_PARTY_NOTICES'), ($notices -join "`n") + "`n", $utf8)
} finally {
    Pop-Location
}
