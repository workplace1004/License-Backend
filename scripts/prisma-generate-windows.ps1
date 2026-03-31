# Prisma on Windows can fail with EBUSY when renaming *.tmp* downloads to final engine
# binaries. Engines may live under node_modules\@prisma\engines and/or node_modules\prisma.
# This script runs prisma generate in a loop and copies *.tmp<PID> -> final name in each folder.
$ErrorActionPreference = 'Continue'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

$nodeModules = Join-Path $root 'node_modules'
if (-not (Test-Path $nodeModules)) {
  Write-Error ('Missing ' + $nodeModules + ' - run npm install in license-server first.')
  exit 1
}

# Prisma 5+ may place engines in either path (generate often uses node_modules\prisma).
$EngineDirs = @(
  (Join-Path $root 'node_modules\@prisma\engines'),
  (Join-Path $root 'node_modules\prisma')
)

foreach ($d in $EngineDirs) {
  if (Test-Path $d) {
    Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
      Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue
    }
  }
}

# Names like: query_engine-windows.dll.node.tmp12345 -> query_engine-windows.dll.node
$TmpPattern = '^(.+)\.tmp\d+$'

function Repair-AllPrismaEngineTmps {
  param([string[]]$Dirs)

  $repaired = $false
  foreach ($enginesDir in $Dirs) {
    if (-not (Test-Path $enginesDir)) { continue }

    $rows = @()
    Get-ChildItem -Path $enginesDir -File -ErrorAction SilentlyContinue | ForEach-Object {
      if ($_.Name -match $TmpPattern) {
        $rows += [PSCustomObject]@{ File = $_; Base = $Matches[1] }
      }
    }
    if ($rows.Count -eq 0) { continue }

    foreach ($grp in ($rows | Group-Object -Property Base)) {
      $best = $grp.Group | Sort-Object { $_.File.Length } -Descending | Select-Object -First 1
      $tmpFile = $best.File
      $destName = $grp.Name
      $dest = Join-Path $enginesDir $destName

      Write-Host ('Completing engine: ' + $tmpFile.Name + ' -> ' + $destName + ' in ' + $enginesDir + ' (EBUSY workaround)...')
      if (Test-Path $dest) {
        attrib -R $dest 2>$null
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
      }
      Copy-Item -LiteralPath $tmpFile.FullName -Destination $dest -Force
      Remove-Item -LiteralPath $tmpFile.FullName -Force -ErrorAction SilentlyContinue
      foreach ($row in $grp.Group) {
        if ($row.File.FullName -ne $tmpFile.FullName -and (Test-Path $row.File.FullName)) {
          Remove-Item -LiteralPath $row.File.FullName -Force -ErrorAction SilentlyContinue
        }
      }
      $repaired = $true
    }
  }
  return $repaired
}

$maxAttempts = 10
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
  Write-Host ('Running prisma generate (attempt ' + $attempt + ' of ' + $maxAttempts + ')...')
  & npx prisma generate 2>&1 | Write-Host
  if ($LASTEXITCODE -eq 0) {
    Write-Host 'Prisma generate succeeded.'
    exit 0
  }
  if (-not (Repair-AllPrismaEngineTmps -Dirs $EngineDirs)) {
    Write-Host 'No Prisma engine .tmp files left to repair.'
    break
  }
}

Write-Host 'Prisma generate still failed. On Windows use: npm run generate:win. Also add an antivirus exclusion for license-server\node_modules, or use Node 20/22 LTS.'
exit 1
