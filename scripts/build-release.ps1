$ErrorActionPreference = "Stop"

$clientRoot = Split-Path -Parent $PSScriptRoot
Push-Location $clientRoot

try {
    New-Item -ItemType Directory -Force -Path "dist" | Out-Null

    $targets = @(
        @{ OS = "linux";   Arch = "amd64"; Suffix = "" },
        @{ OS = "linux";   Arch = "arm64"; Suffix = "" },
        @{ OS = "darwin";  Arch = "amd64"; Suffix = "" },
        @{ OS = "darwin";  Arch = "arm64"; Suffix = "" },
        @{ OS = "windows"; Arch = "amd64"; Suffix = ".exe" },
        @{ OS = "windows"; Arch = "arm64"; Suffix = ".exe" }
    )

    $env:CGO_ENABLED = "0"
    foreach ($target in $targets) {
        $env:GOOS = $target.OS
        $env:GOARCH = $target.Arch
        $output = "dist/syndichan-node-$($target.OS)-$($target.Arch)$($target.Suffix)"
        Write-Host "building $output"
        & go build -trimpath "-ldflags=-s -w" -o $output ./cmd/syndichan-node
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $($target.OS)/$($target.Arch)"
        }
    }
}
finally {
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}
