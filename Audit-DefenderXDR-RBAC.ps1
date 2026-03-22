# Compatível com PowerShell 5.1+ e PowerShell 7+
# Módulos necessários: Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
<#
.SYNOPSIS
    Audita permissões do Microsoft Defender XDR e gera relatório HTML.
.DESCRIPTION
    Mapeia Entra ID Roles, Unified RBAC, grupos, workloads.
    Executa KQL no Advanced Hunting. Gera HTML com SVG e gráficos.
.PARAMETER OutputPath
    Caminho de saída. Default: pasta atual.
.PARAMETER DaysBack
    Dias de histórico. Default: 30.
.NOTES
    Permissões: Directory.Read.All, RoleManagement.Read.All, ThreatHunting.Read.All
    Desenvolvido por Rafael Franca - ODEFENDER | github.com/odefender
#>
[CmdletBinding()]
param([string]$OutputPath = (Get-Location).Path, [int]$DaysBack = 30)

$ErrorActionPreference = "Stop"

# Validar módulos necessários - tentar importar, instalar se ausente
$requiredModules = @("Microsoft.Graph.Authentication","Microsoft.Graph.Identity.DirectoryManagement","Microsoft.Graph.Identity.Governance","Microsoft.Graph.Groups","Microsoft.Graph.DirectoryObjects","Microsoft.Graph.Security")
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
        Write-Host "[!] Módulo $mod não encontrado. Instalando..." -ForegroundColor Yellow
        try {
            Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop
            Write-Host "  [OK] $mod instalado." -ForegroundColor Green
        } catch {
            Write-Host "[ERRO] Falha ao instalar $mod : $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Execute manualmente: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
            exit 1
        }
    }
    Import-Module $mod -ErrorAction SilentlyContinue
}

$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFile = Join-Path $OutputPath "DefenderXDR-RBAC-Audit_$ts.html"

# Roles que concedem acesso ao Defender XDR (documentadas em manage-rbac)
$secRoles = @("Global Administrator","Global Reader","Security Administrator","Security Operator","Security Reader","Compliance Administrator","Compliance Data Administrator")

# URLs verificadas do portal
$portal = @{
    Perms   = "https://security.microsoft.com/securitysettings/mtp_roles"
    Hunt    = "https://security.microsoft.com/v2/advanced-hunting"
    Audit   = "https://security.microsoft.com/auditlogsearch"
    Incidents = "https://security.microsoft.com/incidents"
    Entra   = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles"
}

function Write-Step($M){Write-Host "`n[$((Get-Date).ToString('HH:mm:ss'))] $M" -ForegroundColor Cyan}
function Write-OK($M){Write-Host "  [OK] $M" -ForegroundColor Green}
function Write-Warn($M){Write-Host "  [!] $M" -ForegroundColor Yellow}
function Invoke-KQL($Q){(Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Body (@{Query=$Q}|ConvertTo-Json)).results}
function Mask($Id){if($Id.Length -gt 12){"$($Id.Substring(0,8))...$($Id.Substring($Id.Length-4))"}else{$Id}}

# ═══════════════════════════════════════════
# 1. AUTENTICAÇÃO
# ═══════════════════════════════════════════
Write-Step "Autenticação..."
$scopes = @("Directory.Read.All","RoleManagement.Read.All","ThreatHunting.Read.All")
$ctx = Get-MgContext
if (-not $ctx) { Connect-MgGraph -Scopes ($scopes -join ",") -UseDeviceCode -NoWelcome; $ctx = Get-MgContext }
$miss = $scopes | Where-Object { $_ -notin $ctx.Scopes }
if ($miss.Count -gt 0) { Disconnect-MgGraph -EA SilentlyContinue|Out-Null; Connect-MgGraph -Scopes ($scopes -join ",") -UseDeviceCode -NoWelcome; $ctx = Get-MgContext }
Write-OK "$($ctx.Account) | Tenant: $($ctx.TenantId)"

# ═══════════════════════════════════════════
# 2. WORKLOADS ATIVOS
# ═══════════════════════════════════════════
Write-Step "Workloads..."
$wl = @(
    @{N="MDE";F="Defender for Endpoint";T="DeviceInfo";C="#4fc3f7"},
    @{N="MDO";F="Defender for Office 365";T="EmailEvents";C="#81c784"},
    @{N="MDI";F="Defender for Identity";T="IdentityDirectoryEvents";C="#ffb74d"},
    @{N="MDCA";F="Defender for Cloud Apps";T="CloudAppEvents";C="#ce93d8"}
)
foreach($w in $wl){try{$r=Invoke-KQL "$($w.T)|take 1";$w.A=$r.Count -gt 0}catch{$w.A=$false};Write-OK "$($w.N): $(if($w.A){'Ativo'}else{'Sem dados'})"}

# ═══════════════════════════════════════════
# 3. ENTRA ID ROLES + PRINCIPALS
# ═══════════════════════════════════════════
Write-Step "Entra ID Roles..."
$rd = @(); $allDefs = Get-MgRoleManagementDirectoryRoleDefinition -All; $allAsgn = Get-MgRoleManagementDirectoryRoleAssignment -All
foreach($rn in $secRoles){
    $def = $allDefs|Where-Object{$_.DisplayName -eq $rn}; if(-not $def){continue}
    $asgn = $allAsgn|Where-Object{$_.RoleDefinitionId -eq $def.Id}
    if($asgn.Count -eq 0){$rd+=[PSCustomObject]@{Role=$rn;Typ="-";Name="(vazio)";Id="-"};Write-OK "$rn : vazio"}
    else{foreach($a in $asgn){try{$p=Get-MgDirectoryObject -DirectoryObjectId $a.PrincipalId -EA Stop;$t=$p.AdditionalProperties.'@odata.type'-replace'#microsoft.graph.','';$n=$p.AdditionalProperties.displayName}catch{$t="?";$n=$a.PrincipalId};$rd+=[PSCustomObject]@{Role=$rn;Typ=$t;Name=$n;Id=Mask $a.PrincipalId};Write-OK "$rn : [$t] $n"}}
}
$nU=($rd|Where-Object{$_.Typ -eq 'user' -and $_.Name -ne '(vazio)'}).Count
$nG=($rd|Where-Object{$_.Typ -eq 'group'}).Count
$nS=($rd|Where-Object{$_.Typ -eq 'servicePrincipal'}).Count

# ═══════════════════════════════════════════
# 4. DEFENDER UNIFIED RBAC
# ═══════════════════════════════════════════
Write-Step "Defender Unified RBAC..."
$rb = @(); $dGrp = [System.Collections.Generic.HashSet[string]]::new()
try{
    $dR = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/defender/roleDefinitions" -EA Stop
    $dA = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/defender/roleAssignments" -EA Stop
    foreach($role in $dR.value){$pm=($role.rolePermissions|ForEach-Object{$_.allowedResourceActions})-join", "
        $as=$dA.value|Where-Object{$_.roleDefinitionId -eq $role.id}
        if($as.Count -eq 0){$rb+=[PSCustomObject]@{CR=$role.displayName;Pm=$pm;To="(vazio)";TT="-";Mb="-"}}
        else{foreach($a in $as){foreach($pid2 in $a.principalIds){
            try{$o=Get-MgDirectoryObject -DirectoryObjectId $pid2 -EA Stop;$ot=$o.AdditionalProperties.'@odata.type'-replace'#microsoft.graph.','';$on=$o.AdditionalProperties.displayName;$ml="-"
                if($ot -eq 'group'){[void]$dGrp.Add($on);$ms=Get-MgGroupMember -GroupId $pid2 -EA SilentlyContinue;$ml=($ms|ForEach-Object{$_.AdditionalProperties.displayName})-join", ";if(!$ml){$ml="(vazio)"}}
                $rb+=[PSCustomObject]@{CR=$role.displayName;Pm=$pm;To=$on;TT=$ot;Mb=$ml};Write-OK "'$($role.displayName)' -> [$ot] $on"
            }catch{Write-Warn "Erro $pid2"}
        }}}}
}catch{Write-Warn "RBAC: $($_.Exception.Message)";$rb+=[PSCustomObject]@{CR="(indisponível)";Pm="-";To="-";TT="-";Mb="-"}}

# ═══════════════════════════════════════════
# 4b. MAPEAMENTO DE CAMINHOS DE ACESSO
# ═══════════════════════════════════════════
Write-Step "Mapeando caminhos de acesso..."
$accessPaths = @()
$levelMap = @{
    "Global Administrator"="FULL ADMIN";"Security Administrator"="FULL SECURITY";
    "Security Operator"="OPERATOR";"Security Reader"="READ-ONLY";
    "Global Reader"="READ-ONLY";"Compliance Administrator"="COMPLIANCE";
    "Compliance Data Administrator"="COMPLIANCE DATA"
}
$levelColors = @{
    "FULL ADMIN"="#f85149";"FULL SECURITY"="#ff7b72";"OPERATOR"="#ffa657";
    "READ-ONLY"="#3fb950";"COMPLIANCE"="#a5d6ff";"COMPLIANCE DATA"="#7ee787"
}

# Entra ID Roles diretas
foreach($entry in $rd){
    if($entry.Name -eq "(vazio)"){continue}
    $lvl = if($levelMap.ContainsKey($entry.Role)){$levelMap[$entry.Role]}else{"OTHER"}
    $accessPaths += [PSCustomObject]@{
        Principal=$entry.Name; PType=$entry.Typ; Level=$lvl
        Role=$entry.Role; Path="Entra ID Role (direto)"; Group="-"
    }
}

# RBAC via grupo
foreach($rbEntry in $rb){
    if($rbEntry.To -eq "(vazio)" -or $rbEntry.To -eq "(indisponível)"){continue}
    if($rbEntry.TT -eq "group" -and $rbEntry.Mb -and $rbEntry.Mb -ne "-" -and $rbEntry.Mb -ne "(vazio)"){
        $permS = ($rbEntry.Pm -replace 'microsoft\.xdr/','') -replace '/\*/manage',''
        foreach($memberName in ($rbEntry.Mb -split ",")){
            $mn = $memberName.Trim()
            if($mn){
                $accessPaths += [PSCustomObject]@{
                    Principal=$mn; PType="user (via grupo)"; Level="RBAC ($permS)"
                    Role="RBAC: $($rbEntry.CR)"; Path="Grupo -> RBAC Role"; Group=$rbEntry.To
                }
            }
        }
    }
}

$uniquePrincipals = ($accessPaths | Select-Object -Property Principal -Unique).Count
Write-OK "Caminhos mapeados: $($accessPaths.Count) para $uniquePrincipals principals"

# ═══════════════════════════════════════════
# 4c. QUEM ALTEROU ROLES/RBAC (evidências)
# ═══════════════════════════════════════════
Write-Step "Coletando evidências de alterações RBAC..."
$rbacChanges = @()
try {
    $rbacChanges = Invoke-KQL @'
CloudAppEvents
| where ActionType in ("Add member to role.", "Remove member from role.", "AddRole", "EditRole", "DeleteRole")
| extend RoleName = parse_json(tostring(RawEventData.ModifiedProperties[1])).NewValue
| extend TargetName = tostring(RawEventData.Target[3].ID)
| extend TargetType = tostring(RawEventData.Target[2].ID)
| project Timestamp, ActionType, QuemFez=AccountDisplayName, RoleName, TargetName, TargetType, IP=IPAddress, Country=CountryCode
| sort by Timestamp desc
'@
    Write-OK "Alterações de role/RBAC: $($rbacChanges.Count)"
} catch { Write-Warn "Erro ao buscar alterações RBAC" }

# Alterações nos grupos do RBAC
$rbacGroupChanges = @()
if ($dGrp.Count -gt 0) {
    $grpFilter = ($dGrp | ForEach-Object { "`"$_`"" }) -join ","
    try {
        $rbacGroupChanges = Invoke-KQL "CloudAppEvents | where ActionType in ('Add member to group.','Remove member from group.') | extend GroupName = parse_json(tostring(RawEventData.ModifiedProperties[1])).NewValue | where GroupName has_any ($grpFilter) | extend TargetUPN = tostring(RawEventData.ObjectId) | project Timestamp, ActionType, QuemFez=AccountDisplayName, GroupName, TargetUPN, IP=IPAddress | sort by Timestamp desc"
        Write-OK "Alterações em grupos RBAC: $($rbacGroupChanges.Count)"
    } catch { Write-Warn "Erro ao buscar alterações de grupo RBAC" }
}

$totalRbacChanges = $rbacChanges.Count + $rbacGroupChanges.Count
Write-OK "Total evidências RBAC: $totalRbacChanges"

# ═══════════════════════════════════════════
# 5. KQL
# ═══════════════════════════════════════════
Write-Step "Queries KQL..."
$gf="";if($dGrp.Count -gt 0){$gl=($dGrp|Select-Object -Unique|ForEach-Object{"`"$_`""})-join", ";$gf="| where GroupName has_any ($gl)";Write-OK "Filtro: $gl"}else{$gf="// Sem grupo especifico";Write-Warn "Sem grupo RBAC"}

$kqlFull=@"
CloudAppEvents | where ActionType in ("Add member to role.","Remove member from role.") | extend RoleName = parse_json(tostring(RawEventData.ModifiedProperties[1])).NewValue | where RoleName has_any ("Security Administrator","Security Operator","Security Reader","Global Administrator","Global Reader","Compliance Administrator","Compliance Data Administrator") | project Timestamp, Cenario="1-Role Entra ID", Acao=ActionType, QuemFez=AccountDisplayName, Detalhe=RoleName, Alvo=tostring(RawEventData.ObjectId), IP=IPAddress
| union (CloudAppEvents | where ActionType in ("Add member to group.","Remove member from group.") | extend GroupName = parse_json(tostring(RawEventData.ModifiedProperties[1])).NewValue | project Timestamp, Cenario="2-Grupo Entra ID", Acao=ActionType, QuemFez=AccountDisplayName, Detalhe=GroupName, Alvo=tostring(RawEventData.ObjectId), IP=IPAddress)
| union (CloudAppEvents | where ActionType in ("AddRole","EditRole","DeleteRole") | project Timestamp, Cenario="3-Custom Role RBAC", Acao=ActionType, QuemFez=AccountDisplayName, Detalhe=tostring(RawEventData), Alvo="", IP=IPAddress)
| union (IdentityDirectoryEvents | where ActionType == "Group Membership changed" | extend GroupName = tostring(AdditionalFields['TO.GROUP']) | extend RF = tostring(AdditionalFields['FROM.GROUP']) | project Timestamp, Cenario="4-Grupo AD on-prem", Acao=ActionType, QuemFez=AccountDisplayName, Detalhe=coalesce(GroupName,RF), Alvo=tostring(AdditionalFields['TARGET_OBJECT.USER']), IP=IPAddress)
| sort by Timestamp desc
"@

$kqlRule = $kqlFull -replace '2-Grupo Entra ID','2-Grupo RBAC'
if ($dGrp.Count -gt 0) {
    $kqlRule = $kqlRule -replace '\| project Timestamp, Cenario="2-Grupo RBAC"', "$gf`n| project Timestamp, Cenario=`"2-Grupo RBAC`""
}

# ═══════════════════════════════════════════
# 6. EXECUTAR
# ═══════════════════════════════════════════
Write-Step "Executando Advanced Hunting..."
$ev=@();try{$ev=Invoke-KQL $kqlFull;Write-OK "Eventos: $($ev.Count)"}catch{Write-Warn "Erro: $($_.Exception.Message)"}
$evS=@{};foreach($e in $ev){$c=$e.Cenario;if(-not $evS.ContainsKey($c)){$evS[$c]=0};$evS[$c]++}

$tl=@();try{$tl=Invoke-KQL "CloudAppEvents|where ActionType in ('Add member to role.','Remove member from role.','Add member to group.','Remove member from group.','AddRole','EditRole','DeleteRole')|summarize Ev=count() by Dia=bin(Timestamp,1d)|sort by Dia asc";Write-OK "Timeline: $($tl.Count) dias"}catch{}
$ta=@();try{$ta=Invoke-KQL "CloudAppEvents|where ActionType in ('Add member to role.','Remove member from role.','Add member to group.','Remove member from group.','AddRole','EditRole','DeleteRole')|summarize N=count() by Quem=AccountDisplayName|sort by N desc|take 10"}catch{}

# ═══════════════════════════════════════════
# 7. HTML REPORT
# ═══════════════════════════════════════════
Write-Step "Gerando relatório..."
$tRA=($rd|Where-Object{$_.Name -ne "(vazio)"}).Count; $tRB=($rb|Where-Object{$_.To -ne "(vazio)" -and $_.To -ne "(indisponível)"}).Count; $tEv=$ev.Count; $aWL=($wl|Where-Object{$_.A}).Count
$rC=@{"Global Administrator"="#f85149";"Security Administrator"="#ff7b72";"Security Operator"="#ffa657";"Security Reader"="#d29922";"Global Reader"="#79c0ff";"Compliance Administrator"="#a5d6ff";"Compliance Data Administrator"="#7ee787"}

# ── SVG: Mapa de Permissões (Esquerda: Workloads | Centro: XDR | Direita: Roles/Grupos/Users)
$svgNodes = ""; $svgLines = ""; $sy = 50; $wlPositions = @()

# Workloads (esquerda) - com tooltip de detalhes
foreach($w in $wl){$op=if($w.A){"1"}else{".3"};$sc=if($w.A){$w.C}else{"#484f58"};$stTxt=if($w.A){"Ativo - dados disponíveis no Advanced Hunting"}else{"Sem dados - verificar conector"}
$svgNodes+="<g transform='translate(10,$sy)' opacity='$op' style='cursor:pointer'><title>$($w.F)`n$stTxt</title><rect width='120' height='30' rx='5' fill='#161b22' stroke='$sc' stroke-width='1.2'/><text x='7' y='13' fill='$sc' font-family='Segoe UI' font-size='7' font-weight='700'>$($w.N)</text><text x='7' y='24' fill='#6e7681' font-family='Segoe UI' font-size='5.5'>$($w.F)</text>"
$svgNodes+="<circle cx='112' cy='8' r='3' fill='$(if($w.A){"#3fb950"}else{"#f85149"})'/></g>`n"
$wlPositions += @{Y=$sy;C=$sc;Op=$op}
$sy+=36}

# Roles/Grupos (direita) - coletar com detalhes para tooltip
$ry = 50; $rightNodes = @()
foreach($rn in ($rd|Where-Object{$_.Name -ne "(vazio)"}|Select-Object -Property Role -Unique).Role){
    $mc=($rd|Where-Object{$_.Role -eq $rn -and $_.Name -ne "(vazio)"}).Count
    $co=if($rC.ContainsKey($rn)){$rC[$rn]}else{"#8b949e"}
    $memberNames=($rd|Where-Object{$_.Role -eq $rn -and $_.Name -ne "(vazio)"}|ForEach-Object{"• $($_.Name) ($($_.Typ))"})-join"`n"
    $rightNodes += @{Y=$ry;N=$rn;C=$co;Cnt=$mc;Type="role";Tip="$rn (Entra ID Role)`nEscopo: TODOS os workloads (MDE, MDO, MDI, MDCA)`n$mc membro(s):`n$memberNames"}
    $ry+=28
}
foreach($g in $dGrp){
    $rbM=$rb|Where-Object{$_.To -eq $g}|Select-Object -First 1
    $gMemberCount=if($rbM.Mb -and $rbM.Mb -ne "(vazio)" -and $rbM.Mb -ne "-"){($rbM.Mb -split ",").Count}else{0}
    $scopeTxt = if($rbM.Pm -match '\*/'){"TODOS os workloads (escopo global)"}else{"Escopo restrito - ver permissões"}
    $permShort = ($rbM.Pm -replace 'microsoft\.xdr/','') -replace '/\*/manage',''
    $gTip="Grupo RBAC: $g`nCustom Role: $($rbM.CR)`nEscopo: $scopeTxt`nPermissões: $permShort`nMembros ($gMemberCount): $($rbM.Mb)"
    $rightNodes += @{Y=$ry;N="$g";C="#3fb950";Cnt=$gMemberCount;Type="group";Tip=$gTip;Perms=$permShort}
    $ry+=28
}

# Centro: XDR - calcular APÓS ambos os lados
$centerY = [Math]::Max(60, [Math]::Floor(([Math]::Max($sy, $ry) / 2) - 25))
$svgNodes+="<g style='cursor:pointer'><title>Microsoft Defender XDR`nPortal: security.microsoft.com`nModelo: Unified RBAC`n`nO acesso é controlado por:`n- Entra ID Roles (à direita)`n- Grupos do Unified RBAC (à direita)</title>"
$svgNodes+="<rect x='190' y='$centerY' width='90' height='40' rx='7' fill='#21262d' stroke='#58a6ff' stroke-width='1.2'/>"
$svgNodes+="<text x='235' y='$($centerY+18)' fill='#58a6ff' font-family='Segoe UI' font-size='7' text-anchor='middle' font-weight='700'>DEFENDER XDR</text>"
$svgNodes+="<text x='235' y='$($centerY+30)' fill='#6e7681' font-family='Segoe UI' font-size='5.5' text-anchor='middle'>Unified RBAC</text></g>`n"

# Linhas workloads → centro
foreach($wp in $wlPositions){
    $svgLines+="<line x1='130' y1='$($wp.Y+15)' x2='190' y2='$($centerY+20)' stroke='$($wp.C)' stroke-width='.6' stroke-dasharray='3' opacity='$($wp.Op)'/>`n"
}

# Nós direita + linhas centro → roles/grupos
foreach($rn in $rightNodes){
    $typeIcon=if($rn.Type -eq "role"){"&#x1F511;"}else{"&#x1F465;"}
    $cntBadge=""
    if($rn.Cnt -gt 0){
        $badgeFill=if($rn.Type -eq "group"){"#3fb950"}else{$rn.C}
        $cntBadge="<rect x='133' y='3' width='18' height='14' rx='7' fill='${badgeFill}25' stroke='$badgeFill' stroke-width='.5'/><text x='142' y='13' fill='$badgeFill' font-family='Segoe UI' font-size='6.5' text-anchor='middle' font-weight='700'>$($rn.Cnt)</text>"
    }
    # Tooltip com detalhes dos membros
    $tipEscaped = $rn.Tip -replace "'","&#39;"
    $svgNodes+="<g transform='translate(320,$($rn.Y))' style='cursor:pointer'><title>$tipEscaped</title>"
    $svgNodes+="<rect width='155' height='20' rx='4' fill='$($rn.C)08' stroke='$($rn.C)' stroke-width='.7'/>"
    $svgNodes+="<text x='4' y='13' fill='$($rn.C)' font-family='Segoe UI' font-size='6' font-weight='600'>$typeIcon $($rn.N)</text>"
    $svgNodes+="$cntBadge</g>`n"
    # Para grupos RBAC, adicionar badges de permissão abaixo do nó
    if($rn.Type -eq 'group' -and $rn.Perms){
        $svgNodes+="<text x='325' y='$($rn.Y+28)' fill='#3fb95080' font-family='Segoe UI' font-size='4.5' font-style='italic'>$($rn.Perms)</text>`n"
        $ry+=8  # espaço extra para o texto de permissões
    }
    $svgLines+="<line x1='280' y1='$($centerY+20)' x2='320' y2='$($rn.Y+10)' stroke='$($rn.C)' stroke-width='.5' stroke-dasharray='3' opacity='.3'/>`n"
}

# Combinar: linhas atrás, nós na frente
$svg1 = $svgLines + $svgNodes

# Legenda do SVG - redesenhada com cores reais dos nós
$legendY = [Math]::Max($sy, $ry) + 24
$svg1+="<line x1='10' y1='$($legendY-8)' x2='510' y2='$($legendY-8)' stroke='#21262d' stroke-width='.5'/>`n"
$svg1+="<g transform='translate(10,$legendY)' font-family='Segoe UI'>`n"
# Status dos workloads
$svg1+="<text x='0' y='10' fill='#484f58' font-size='7' font-weight='700'>STATUS:</text>"
$svg1+="<circle cx='50' cy='7' r='3' fill='#3fb950'/><text x='57' y='10' fill='#6e7681' font-size='7'>Ativo</text>"
$svg1+="<circle cx='88' cy='7' r='3' fill='#f85149'/><text x='95' y='10' fill='#6e7681' font-size='7'>Inativo</text>`n"
# Tipos de nó
$svg1+="<text x='140' y='10' fill='#484f58' font-size='7' font-weight='700'>TIPO:</text>"
$svg1+="<rect x='170' y='1' width='8' height='8' rx='2' fill='#f8514920' stroke='#f85149' stroke-width='.5'/><text x='182' y='10' fill='#6e7681' font-size='7'>Entra ID Role</text>"
$svg1+="<rect x='240' y='1' width='8' height='8' rx='2' fill='#3fb95020' stroke='#3fb950' stroke-width='.5'/><text x='252' y='10' fill='#6e7681' font-size='7'>Grupo RBAC</text>`n"
# Badge
$svg1+="<text x='320' y='10' fill='#484f58' font-size='7' font-weight='700'>BADGE:</text>"
$svg1+="<rect x='355' y='1' width='14' height='10' rx='5' fill='#58a6ff25' stroke='#58a6ff' stroke-width='.5'/><text x='362' y='9' fill='#58a6ff' font-size='6' text-anchor='middle'>N</text>"
$svg1+="<text x='375' y='10' fill='#6e7681' font-size='7'>= principals atribuídos</text>`n"
# Interação
$svg1+="<text x='0' y='24' fill='#484f58' font-size='6' font-style='italic'>Passe o mouse sobre qualquer elemento para ver detalhes completos (membros, permissões, status)</text>`n"
$svg1+="</g>`n"
$svgH1 = $legendY + 40

# ── Tabela: RBAC do Defender XDR (FOCO PRINCIPAL)
$tblRbacXdr = ""
foreach($role in $dR.value){
    $permShort = (($role.rolePermissions | ForEach-Object { $_.allowedResourceActions }) -replace 'microsoft\.xdr/','') -replace '/\*/manage',''
    $assignments = $dA.value | Where-Object { $_.roleDefinitionId -eq $role.id }
    if ($assignments.Count -eq 0) {
        $tblRbacXdr += "<tr><td style='color:#3fb950;font-weight:600'>$($role.displayName)</td><td class='s'>$permShort</td><td colspan='3' style='color:#6e7681'>(sem assignment)</td></tr>`n"
    } else {
        foreach($a in $assignments){
            foreach($pid3 in $a.principalIds){
                $obj3 = Get-MgDirectoryObject -DirectoryObjectId $pid3 -EA SilentlyContinue
                $ot3 = $obj3.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
                $on3 = $obj3.AdditionalProperties.displayName
                $scope3 = if($a.appScopeIds -contains "/"){"Global (todos workloads)"}else{$a.appScopeIds -join ","}
                $memberList3 = "-"
                if($ot3 -eq 'group'){
                    $ms3 = Get-MgGroupMember -GroupId $pid3 -EA SilentlyContinue
                    $memberList3 = ($ms3 | ForEach-Object {"$($_.AdditionalProperties.displayName)"}) -join ", "
                    if(!$memberList3){$memberList3="(vazio)"}
                }
                $typeBC3 = if($ot3 -eq 'group'){"#3fb95033;color:#3fb950"}else{"#1f6feb33;color:#58a6ff"}
                $tblRbacXdr += "<tr><td style='color:#3fb950;font-weight:600'><a href='$($portal.Perms)' target='_blank' style='color:#3fb950;text-decoration:none'>$($role.displayName)</a></td><td class='s'>$permShort</td><td><span style='background:$typeBC3;padding:1px 6px;border-radius:8px;font-size:10px'>$ot3</span> <b>$on3</b></td><td>$scope3</td><td>$memberList3</td></tr>`n"
            }
        }
    }
}

# ── Tabela: Caminhos de Acesso (accessPaths)
$tblDetail=""
foreach($ap in ($accessPaths | Sort-Object Level,Principal)){
    $lvlCol = if($levelColors.ContainsKey($ap.Level)){$levelColors[$ap.Level]}else{"#8b949e"}
    $typeBC = switch -Wildcard ($ap.PType){"user*"{"#1f6feb33;color:#58a6ff"}"group"{"#3fb95033;color:#3fb950"}"servicePrincipal"{"#d2992233;color:#d29922"}default{"#30363d;color:#8b949e"}}
    $pathIcon = if($ap.Path -match "direto"){"&#x2192;"}else{"&#x2192; &#x1F465; &#x2192;"}
    $groupInfo = if($ap.Group -ne "-"){"<br><span style='color:#3fb950;font-size:9px'>via $($ap.Group)</span>"}else{""}
    $tblDetail+="<tr><td><b>$($ap.Principal)</b>$groupInfo</td><td><span style='background:$typeBC;padding:1px 6px;border-radius:8px;font-size:10px'>$($ap.PType)</span></td><td style='color:$lvlCol;font-weight:600'>$($ap.Level)</td><td>$($ap.Role)</td><td class='m'>$pathIcon $($ap.Path)</td></tr>`n"
}

# ── Tabela: Evidências de alteração RBAC
$tblRbacEvidence = ""
$auditBaseUrl = "https://security.microsoft.com/auditlogsearch"
foreach($rc in $rbacChanges){
    $actionColor = if($rc.ActionType -match "Add"){"#3fb950"}elseif($rc.ActionType -match "Remove"){"#f85149"}else{"#d29922"}
    $actionIcon = if($rc.ActionType -match "Add"){"&#x2795;"}elseif($rc.ActionType -match "Remove"){"&#x274C;"}else{"&#x270F;"}
    $ts2 = ([datetime]$rc.Timestamp).ToString("yyyy-MM-dd HH:mm")
    $tblRbacEvidence += "<tr style='border-left:3px solid $actionColor'><td class='m'>$ts2</td><td style='color:$actionColor;font-weight:600'>$actionIcon $($rc.ActionType)</td><td><b>$($rc.QuemFez)</b></td><td>$($rc.RoleName)</td><td>$($rc.TargetName) <span style='color:#6e7681;font-size:9px'>($($rc.TargetType))</span></td><td class='m'>$($rc.IP)</td></tr>`n"
}
foreach($gc in $rbacGroupChanges){
    $actionColor = if($gc.ActionType -match "Add"){"#3fb950"}else{"#f85149"}
    $actionIcon = if($gc.ActionType -match "Add"){"&#x2795;"}else{"&#x274C;"}
    $ts2 = ([datetime]$gc.Timestamp).ToString("yyyy-MM-dd HH:mm")
    $tblRbacEvidence += "<tr style='border-left:3px solid $actionColor'><td class='m'>$ts2</td><td style='color:$actionColor;font-weight:600'>$actionIcon Grupo RBAC</td><td><b>$($gc.QuemFez)</b></td><td>$($gc.GroupName)</td><td>$($gc.TargetUPN)</td><td class='m'>$($gc.IP)</td></tr>`n"
}

# ── SVG: Donut com cores por cenário + legenda integrada
$svgD="";$dC=@{"1-Role Entra ID"="#f85149";"2-Grupo Entra ID"="#58a6ff";"3-Custom Role RBAC"="#3fb950";"4-Grupo AD on-prem"="#d29922"}
$dLabels=@{"1-Role Entra ID"="Atribuição direta de Entra ID Role";"2-Grupo Entra ID"="Alteração de membership em grupo";"3-Custom Role RBAC"="Criação/edição de role no Unified RBAC";"4-Grupo AD on-prem"="Alteração de grupo no Active Directory"}
if($evS.Count -gt 0 -and $tEv -gt 0){$sa=0
foreach($en in $evS.GetEnumerator()){$pc=$en.Value/$tEv;$ea=$sa+($pc*360);$sr=$sa*[Math]::PI/180;$er=$ea*[Math]::PI/180;$cx=90;$cy=90;$rad=70
$x1=$cx+$rad*[Math]::Cos($sr);$y1=$cy+$rad*[Math]::Sin($sr);$x2=$cx+$rad*[Math]::Cos($er);$y2=$cy+$rad*[Math]::Sin($er);$la=if($pc -gt .5){1}else{0};$cl=if($dC.ContainsKey($en.Key)){$dC[$en.Key]}else{"#8b949e"}
if($pc -lt 1){$svgD+="<path d='M $cx $cy L $([Math]::Round($x1,2)) $([Math]::Round($y1,2)) A $rad $rad 0 $la 1 $([Math]::Round($x2,2)) $([Math]::Round($y2,2)) Z' fill='$cl' opacity='.85'><title>$($en.Key): $($en.Value) ($([Math]::Round($pc*100))%)</title></path>`n"}
else{$svgD+="<circle cx='$cx' cy='$cy' r='$rad' fill='$cl' opacity='.85'/>`n"};$sa=$ea}
$svgD+="<circle cx='90' cy='90' r='38' fill='#0d1117'/><text x='90' y='86' fill='#c9d1d9' font-size='18' text-anchor='middle' font-weight='700'>$tEv</text><text x='90' y='102' fill='#8b949e' font-size='9' text-anchor='middle'>eventos</text>`n"
# Legenda com descrição
$ly=20;foreach($en in $evS.GetEnumerator()){$cl=if($dC.ContainsKey($en.Key)){$dC[$en.Key]}else{"#8b949e"};$pp=[Math]::Round(($en.Value/[Math]::Max($tEv,1))*100);$desc=if($dLabels.ContainsKey($en.Key)){$dLabels[$en.Key]}else{$en.Key}
$svgD+="<rect x='195' y='$ly' width='10' height='10' rx='2' fill='$cl'/><text x='210' y='$($ly+9)' fill='#c9d1d9' font-size='10' font-weight='600'>$($en.Key)</text><text x='210' y='$($ly+22)' fill='#6e7681' font-size='8'>$desc - $($en.Value) eventos $($pp)%</text>`n";$ly+=36}}

# ── SVG: Top Atores com cores por volume
$svgA="";if($ta.Count -gt 0){$ma=($ta|ForEach-Object{[int]$_.N}|Measure-Object -Maximum).Maximum;if($ma -eq 0){$ma=1};$ay=10
foreach($ac in $ta){$bw=[Math]::Max(5,[Math]::Floor(([int]$ac.N/$ma)*280));$pct=[Math]::Round(([int]$ac.N/$tEv)*100)
$barCol=if($pct -gt 40){"#f85149"}elseif($pct -gt 20){"#d29922"}else{"#58a6ff"}
$svgA+="<rect x='150' y='$ay' width='$bw' height='18' rx='3' fill='$barCol' opacity='.6'/><text x='145' y='$($ay+13)' fill='#c9d1d9' font-size='9' text-anchor='end'>$($ac.Quem)</text><text x='$($bw+158)' y='$($ay+13)' fill='$barCol' font-size='9' font-weight='600'>$($ac.N) $($pct)%</text>`n";$ay+=26}}
$aH=[Math]::Max(60,($ta.Count*26)+15)

# ── SVG: Timeline com grid e legendas
$svgT="";if($tl.Count -gt 0){$mx=($tl|ForEach-Object{[int]$_.Ev}|Measure-Object -Maximum).Maximum;if($mx -eq 0){$mx=1};$bw=[Math]::Floor(650/[Math]::Max($tl.Count,1));$bx=80
# Grid lines
$svgT+="<text x='10' y='20' fill='#484f58' font-size='8'>$mx</text><line x1='80' y1='18' x2='750' y2='18' stroke='#21262d' stroke-width='.5'/>`n"
$svgT+="<text x='10' y='100' fill='#484f58' font-size='8'>$([Math]::Floor($mx/2))</text><line x1='80' y1='98' x2='750' y2='98' stroke='#21262d' stroke-width='.5'/>`n"
$svgT+="<line x1='80' y1='180' x2='750' y2='180' stroke='#30363d' stroke-width='1'/><line x1='80' y1='18' x2='80' y2='180' stroke='#30363d' stroke-width='1'/>`n"
$svgT+="<text x='10' y='183' fill='#484f58' font-size='8'>0</text>`n"
foreach($td in $tl){$bh=[Math]::Max(3,[Math]::Floor(([int]$td.Ev/$mx)*160));$by=180-$bh;$dl=([datetime]$td.Dia).ToString("MM/dd")
$barC=if([int]$td.Ev -gt ($mx*0.7)){"#f85149"}elseif([int]$td.Ev -gt ($mx*0.3)){"#d29922"}else{"#58a6ff"}
$svgT+="<rect x='$bx' y='$by' width='$([Math]::Max($bw-4,6))' height='$bh' rx='3' fill='$barC' opacity='.7'><title>$dl : $($td.Ev) eventos</title></rect>`n"
$svgT+="<text x='$($bx+($bw/2)-4)' y='$($by-3)' fill='$barC' font-size='8' font-weight='600'>$($td.Ev)</text>`n"
$svgT+="<text x='$($bx+($bw/2)-6)' y='196' fill='#484f58' font-size='7' transform='rotate(-45 $($bx+($bw/2)-6) 196)'>$dl</text>`n";$bx+=$bw}}

# ── Tabela de eventos
$tblEv=($ev|Select-Object -First 50|ForEach-Object{$sv=if($_.Cenario -match "1-Role|3-Custom"){"border-left:3px solid #f85149"}else{"border-left:3px solid #d29922"}
"<tr style='$sv'><td class='m'>$(([datetime]$_.Timestamp).ToString('yyyy-MM-dd HH:mm'))</td><td>$($_.Cenario)</td><td>$($_.Acao)</td><td>$($_.QuemFez)</td><td class='s'>$($_.Detalhe)</td><td>$($_.Alvo)</td><td class='m'>$($_.IP)</td></tr>"})-join"`n"

# Escape KQL
$kH=$kqlFull -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
$kR=$kqlRule -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
$tmask=Mask $ctx.TenantId

# ═══════════════════════════════════════════
# HTML OUTPUT
# ═══════════════════════════════════════════
$htmlContent = @"
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Defender XDR RBAC Audit</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
.c{max-width:1400px;margin:0 auto;padding:20px}
.hd{background:linear-gradient(135deg,#1a1f35,#0a2647);border:1px solid #30363d;border-radius:12px;padding:28px;margin-bottom:20px}
.hd h1{color:#58a6ff;font-size:22px}.hd p{color:#8b949e;font-size:12px;margin-top:4px}
.hd .mt{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap;font-size:11px}
.hd .mt span,.hd .mt a{background:#21262d;padding:3px 10px;border-radius:5px;border:1px solid #30363d;color:#8b949e;text-decoration:none}
.hd .mt a:hover{color:#58a6ff;border-color:#58a6ff}
.cds{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:20px}
.cd{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center;transition:transform .2s}
.cd:hover{transform:translateY(-2px)}.cd .n{font-size:28px;font-weight:bold}.cd .l{color:#8b949e;font-size:10px;margin-top:2px}
.cd.c1 .n{color:#58a6ff}.cd.c2 .n{color:#3fb950}.cd.c3 .n{color:#d29922}.cd.c4 .n{color:#f85149}.cd.c5 .n{color:#ce93d8}
.sc{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:20px;overflow:hidden}
.st{background:#21262d;padding:10px 16px;font-size:13px;font-weight:600;color:#58a6ff;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center}
.st a{font-size:10px;color:#6e7681;text-decoration:none;background:#161b22;padding:2px 8px;border-radius:4px;border:1px solid #30363d}
.st a:hover{color:#58a6ff;border-color:#58a6ff}
.sb{padding:16px;overflow-x:auto}
.rt{background:#0d1117;border-left:3px solid #1f6feb44;border-radius:0 6px 6px 0;padding:12px 14px;margin-bottom:14px;color:#8b949e;font-size:11px;line-height:1.8}
.rt b{color:#c9d1d9}.rt a{color:#58a6ff}.rt code{background:#21262d;padding:1px 4px;border-radius:3px;font-size:10px}
table{width:100%;border-collapse:collapse;font-size:11px}
th{background:#21262d;color:#58a6ff;padding:7px 8px;text-align:left;border-bottom:2px solid #30363d;position:sticky;top:0}
td{padding:6px 8px;border-bottom:1px solid #1c2128}tr:hover{background:#1c2128}
.m{font-family:'Cascadia Code',Consolas,monospace;font-size:10px;color:#6e7681}
.s{font-size:10px;color:#6e7681;max-width:300px;word-wrap:break-word}
.kql{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;font-family:'Cascadia Code',Consolas,monospace;font-size:10px;white-space:pre-wrap;color:#c9d1d9;max-height:300px;overflow-y:auto}
.cp{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:4px 10px;cursor:pointer;font-size:10px;float:right}.cp:hover{background:#30363d;color:#58a6ff}
.ins{background:#0d1117;border-left:3px solid #1f6feb;border-radius:0 6px 6px 0;padding:10px 14px;margin:12px 0;font-size:11px}.ins h3{color:#58a6ff;font-size:12px;margin-bottom:4px}.ins ol{padding-left:16px}.ins code{background:#21262d;padding:1px 4px;border-radius:3px;font-size:10px}
.gr{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:900px){.gr{grid-template-columns:1fr}}
.ft{text-align:center;padding:20px;margin-top:16px;border-top:1px solid #21262d}
.ft .brand{color:#58a6ff;font-size:14px;font-weight:700;margin-bottom:4px}.ft .brand a{color:#58a6ff;text-decoration:none}
.ft .sub{color:#484f58;font-size:10px}
</style></head><body><div class="c">

<div class="hd">
<h1>&#x1F6E1;&#xFE0F; Defender XDR - RBAC Audit Report</h1>
<p>Mapeamento de permissões, grupos, roles, workloads e eventos de alteração de acesso</p>
<div class="mt">
<span>&#x1F4C5; $ts</span><span>&#x1F464; $($ctx.Account)</span><span>&#x1F3E2; $tmask</span><span>&#x1F4CA; $DaysBack dias</span>
<a href="$($portal.Perms)" target="_blank">&#x1F512; Permissions</a>
<a href="$($portal.Hunt)" target="_blank">&#x1F50E; Advanced Hunting</a>
<a href="$($portal.Audit)" target="_blank">&#x1F4DD; Audit Log</a>
<a href="$($portal.Entra)" target="_blank">&#x1F511; Entra Roles</a>
</div></div>

<div class="cds">
<div class="cd c2"><div class="n">$($dR.value.Count)</div><div class="l">Custom Roles<br>no RBAC do XDR</div></div>
<div class="cd c4"><div class="n">$($dGrp.Count)</div><div class="l">Grupos atribuídos<br>no RBAC</div></div>
<div class="cd c1"><div class="n">$tRA</div><div class="l">Entra ID Roles<br>(acesso complementar)</div></div>
<div class="cd c3"><div class="n">$totalRbacChanges</div><div class="l">Alterações RBAC<br>(últimos $DaysBack dias)</div></div>
<div class="cd c5"><div class="n">$aWL<span style='font-size:14px;color:#6e7681'>/4</span></div><div class="l">Workloads<br>Ativos</div></div>
</div>

<!-- S1: RBAC DO DEFENDER XDR (FOCO PRINCIPAL) -->
<div class="sc"><div class="st" style="background:#1a2e1a">&#x1F512; 1. RBAC do Defender XDR - Custom Roles e Assignments<a href="$($portal.Perms)" target="_blank">Permissions &#x2192;</a></div><div class="sb">
<div class="rt" style="border-left-color:#3fb950"><b>FOCO PRINCIPAL:</b> Esta seção mostra as <b>custom roles configuradas no Unified RBAC do Defender XDR</b> (portal security.microsoft.com → Permissions → Roles). Cada role define permissões granulares por categoria: <code>secops</code> (operações SOC), <code>securityposture</code> (postura), <code>configuration</code> (configurações), <code>dataops</code> (dados). As roles são atribuídas a <b>grupos de segurança</b> do Entra ID - qualquer membro do grupo herda as permissões.<br><br>
<b>Achados:</b> <b>$($dR.value.Count)</b> custom role(s) configurada(s), <b>$($dGrp.Count)</b> grupo(s) atribuído(s).<br>
&#x1F517; <a href="$($portal.Perms)" target="_blank">Abrir Permissions no Portal</a> | &#x1F4D6; <a href="https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles" target="_blank">Ref: Custom RBAC Roles</a></div>
<div style="overflow:auto"><table style="min-width:900px"><thead><tr><th style="min-width:120px">Custom Role</th><th style="min-width:200px">Permissões</th><th style="min-width:180px">Atribuída a</th><th style="min-width:140px">Escopo</th><th style="min-width:200px">Membros (acesso efetivo)</th></tr></thead><tbody>
$tblRbacXdr
</tbody></table></div></div></div>

<!-- S1b: EVIDÊNCIAS RBAC -->

<!-- S1c: ENTRA ID ROLES QUE CONTROLAM O XDR -->
<div class="sc"><div class="st">&#x1F511; 1c. Entra ID Roles que controlam acesso ao Defender XDR<a href="$($portal.Entra)" target="_blank">Entra ID &#x2192;</a></div><div class="sb">
<div class="rt"><b>Relação com o RBAC:</b> Além das custom roles do Unified RBAC (seção 1), o Defender XDR também respeita as <b>Entra ID Roles globais</b>. Um usuário com <b>Security Administrator</b> tem acesso total ao portal <b>mesmo sem nenhuma custom role RBAC atribuída</b>. Por isso é essencial monitorar ambas as fontes de acesso. A tabela mostra o nível de acesso efetivo de cada principal no contexto do Defender XDR.<br><br>
<b>Achados:</b> <b>$uniquePrincipals</b> principals com <b>$($accessPaths.Count)</b> caminhos de acesso ao XDR. $nU usuários, $nS service principals.$(if($nS -gt 2){" &#x26A0;&#xFE0F; <b>$nS SPs com acesso privilegiado ao XDR</b>."})</div>
&#x1F4D6; <a href="https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference" target="_blank">Ref: Entra ID Roles</a> | <a href="https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles" target="_blank">Custom RBAC</a></div>
<div style="max-height:500px;overflow:auto"><table style="min-width:800px"><thead><tr><th style="min-width:180px">Principal</th><th style="min-width:100px">Tipo</th><th style="min-width:120px">Nível de Acesso</th><th style="min-width:180px">Role / RBAC</th><th style="min-width:180px">Caminho</th></tr></thead><tbody>
$tblDetail
</tbody></table></div></div></div>

<!-- S1b: EVIDÊNCIAS RBAC -->
<div class="sc"><div class="st">&#x1F6A8; 1b. Quem criou, alterou ou removeu acessos RBAC<a href="$($portal.Audit)" target="_blank">Audit Log &#x2192;</a></div><div class="sb">
<div class="rt"><b>Evidências de alteração:</b> Mostra <b>especificamente</b> quem criou, modificou ou removeu roles e acessos RBAC. Foco em ações de <b>alto impacto</b>: atribuição/remoção de Entra ID Roles e criação/edição de custom roles.$(if($dGrp.Count -gt 0){" Inclui alterações nos grupos do RBAC: <b>$($dGrp -join ', ')</b>."})<br><br>
<b>Total:</b> <b>$totalRbacChanges</b> alterações detectadas. <span style="color:#3fb950">&#x2795; adição</span> | <span style="color:#f85149">&#x274C; remoção</span> | <span style="color:#d29922">&#x270F; edição</span><br>
&#x1F517; <a href="$auditBaseUrl" target="_blank">Audit Log</a> | <a href="$($portal.Hunt)" target="_blank">Advanced Hunting</a></div>
$(if($tblRbacEvidence){"<div style='overflow:auto'><table style='min-width:800px'><thead><tr><th style='min-width:120px'>Quando</th><th style='min-width:140px'>Ação</th><th style='min-width:140px'>Quem Fez</th><th style='min-width:140px'>Role</th><th style='min-width:180px'>Alvo</th><th style='min-width:100px'>IP</th></tr></thead><tbody>$tblRbacEvidence</tbody></table></div>"}else{"<div style='background:#21262d;border-radius:6px;padding:16px;text-align:center'><span style='color:#3fb950;font-size:14px'>&#x2705;</span><br><span style='color:#8b949e'>Nenhuma alteração de RBAC nos últimos $DaysBack dias - estabilidade nas permissões.</span></div>"})
</div></div>

<!-- S2: MAPA VISUAL (contexto do acesso) -->
<div class="sc"><div class="st">&#x1F5FA;&#xFE0F; 2. Arquitetura de Acesso RBAC do Defender XDR<a href="$($portal.Perms)" target="_blank">Portal &#x2192;</a></div><div class="sb">
<div class="rt"><b>Fluxo de acesso ao RBAC:</b> O Defender XDR (centro) protege 4 workloads (esquerda). O acesso é controlado pelo <b>Unified RBAC</b> - as custom roles (seção 1) e Entra ID Roles (seção 1c) estão à direita. O badge numérico mostra quantos principals estão atribuídos a cada role/grupo. Grupos do RBAC (&#x1F465; verde) são o ponto central de controle - adicionar/remover membros desses grupos altera o acesso ao XDR.<br>
&#x1F4D6; <a href="https://learn.microsoft.com/defender-xdr/manage-rbac" target="_blank">Ref: Unified RBAC</a></div>
<svg viewBox="0 0 490 $svgH1" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-family:'Segoe UI',sans-serif">
<text x='65' y='38' fill='#6e7681' font-family='Segoe UI' font-size='6' text-anchor='middle' font-weight='600'>WORKLOADS</text>
<text x='235' y='38' fill='#58a6ff' font-family='Segoe UI' font-size='6' text-anchor='middle' font-weight='600'>PORTAL</text>
<text x='400' y='38' fill='#6e7681' font-family='Segoe UI' font-size='6' text-anchor='middle' font-weight='600'>ROLES / GRUPOS</text>
$svg1
</svg></div></div>

<!-- S3: O QUE MUDOU (pergunta #2 do cliente) -->
<div class="sc"><div class="st">&#x1F50D; 3. Eventos que alteram o RBAC do XDR (últimos $DaysBack dias)<a href="$($portal.Audit)" target="_blank">Audit Log &#x2192;</a></div><div class="sb">
<div class="rt"><b>Impacto no RBAC:</b> Cada evento abaixo representa uma alteração que <b>pode afetar o acesso ao Defender XDR</b> - seja via Entra ID Roles, membership de grupos do RBAC, ou criação/edição de custom roles. Borda <span style="color:#f85149">&#x25CF; vermelha</span> = alto impacto (role/RBAC direto). Borda <span style="color:#d29922">&#x25CF; amarela</span> = médio (grupo). Investigue: (1) conta administrativa esperada? (2) horário normal? (3) IP conhecido?</div>
$(if($tblEv){"<div style='max-height:400px;overflow:auto'><table style='min-width:950px'><thead><tr><th style='min-width:130px'>Timestamp</th><th style='min-width:120px'>Cenário</th><th style='min-width:160px'>Ação</th><th style='min-width:140px'>Quem Fez</th><th style='min-width:200px'>Detalhe</th><th style='min-width:100px'>Alvo</th><th style='min-width:120px'>IP</th></tr></thead><tbody>$tblEv</tbody></table></div>"}else{"<p style='color:#6e7681'>Nenhum evento de alteração nos últimos $DaysBack dias. Execute a query no <a href='$($portal.Hunt)' target='_blank' style='color:#58a6ff'>Advanced Hunting</a> para verificar.</p>"})
</div></div>

<!-- S4: ANÁLISE VISUAL (complemento) -->
<div class="sc"><div class="st">&#x1F4CA; 4. Análise Visual do RBAC</div><div class="sb">
<div class="rt"><b>Padrões de alteração do RBAC:</b> O <b>donut</b> mostra se as alterações no RBAC foram via roles (alto impacto) ou grupos (mais comum). <b>Top atores</b> revela quem mais altera configurações de acesso ao XDR. <b>Timeline</b> identifica picos - dias com volume anômalo de alterações no RBAC do XDR.</div>
<div class="gr">
<div><h4 style="color:#6e7681;font-size:11px;margin-bottom:6px">Distribuição por Cenário</h4>
<svg viewBox="0 0 520 200" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-family:'Segoe UI',sans-serif">$svgD</svg></div>
<div><h4 style="color:#6e7681;font-size:11px;margin-bottom:6px">Top Atores (quem mais alterou)</h4>
<svg viewBox="0 0 500 $aH" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-family:'Segoe UI',sans-serif">$svgA</svg></div>
</div>
<h4 style="color:#6e7681;font-size:11px;margin:14px 0 6px">Timeline de Eventos</h4>
<svg viewBox="0 0 780 210" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-family:'Segoe UI',sans-serif">$svgT</svg>
</div></div>

<!-- S5: COMO MONITORAR (solução proativa) -->
<div class="sc"><div class="st">&#x1F6A8; 5. Monitoramento Contínuo do RBAC - Detection Rule</div><div class="sb">
<div class="rt"><b>Proteger o RBAC do XDR:</b> A query abaixo cria um <b>alerta automático</b> que dispara sempre que alguém alterar o RBAC do Defender XDR - seja criando/editando custom roles, alterando membership de grupos do RBAC, ou atribuindo/removendo Entra ID Roles de segurança. O SOC recebe um incidente na fila do Defender. $(if($dGrp.Count -gt 0){"Filtro de grupos RBAC: <b>$($dGrp -join ', ')</b>."}else{"Sem grupo RBAC específico."})</div>
<div class="ins"><h3>Passo a passo para criar a Detection Rule</h3><ol>
<li>Abrir <a href="$($portal.Hunt)" target="_blank" style="color:#58a6ff">Advanced Hunting</a></li>
<li>Copiar a query abaixo e colar no editor</li>
<li>Clicar em <b>Run query</b> para validar</li>
<li>Clicar em <b>Create detection rule</b></li>
<li>Nome: <code>Alteracao Permissoes Defender XDR</code> | Sev: <code>High</code> | Cat: <code>PrivilegeEscalation</code> | Freq: <code>1h</code></li>
<li>Em Actions: <b>Criar incidente</b></li></ol></div>
<button class="cp" onclick="navigator.clipboard.writeText(document.getElementById('k2').textContent).then(()=>{this.textContent='&#x2705;';setTimeout(()=>{this.textContent='Copiar'},2000)})">Copiar</button>
<div class="kql" id="k2">$kR</div>
<br style="clear:both"><br>
<details style="color:#6e7681;font-size:11px"><summary style="cursor:pointer;color:#58a6ff">&#x26A1; Query de levantamento completo (sem filtros - para investigação)</summary>
<br><button class="cp" onclick="navigator.clipboard.writeText(document.getElementById('k1').textContent).then(()=>{this.textContent='&#x2705;';setTimeout(()=>{this.textContent='Copiar'},2000)})">Copiar</button>
<div class="kql" id="k1">$kH</div>
</details>
</div></div>

<!-- S6: TÉCNICO (referências + permissões) -->
<div class="sc"><div class="st">&#x1F4DA; 6. Informações Técnicas - RBAC APIs e Referências</div><div class="sb">
<div class="rt"><b>APIs utilizadas para auditar o RBAC:</b> O script consulta a API <code>roleManagement/defender</code> (Graph beta) para mapear custom roles e assignments do Unified RBAC. Complementa com <code>roleManagement/directory</code> (Graph v1.0) para Entra ID Roles e <code>runHuntingQuery</code> para eventos via KQL. Todas as operações são <b>somente leitura</b>.</div>
<div class="gr">
<div>
<h4 style="color:#6e7681;font-size:11px;margin-bottom:6px">Permissões do Script</h4>
<table><thead><tr><th>Permissão</th><th>Finalidade</th></tr></thead><tbody>
<tr><td>Directory.Read.All</td><td>Ler grupos, usuários, SPs</td></tr>
<tr><td>RoleManagement.Read.All</td><td>Ler roles (Entra + Defender)</td></tr>
<tr><td>ThreatHunting.Read.All</td><td>Executar KQL</td></tr>
</tbody></table>
</div>
<div>
<h4 style="color:#6e7681;font-size:11px;margin-bottom:6px">Referências Oficiais</h4>
<table><thead><tr><th>Tema</th><th>Link</th></tr></thead><tbody>
<tr><td>Unified RBAC</td><td><a href="https://learn.microsoft.com/defender-xdr/manage-rbac" target="_blank" style="color:#58a6ff">manage-rbac</a></td></tr>
<tr><td>Auditing</td><td><a href="https://learn.microsoft.com/defender-xdr/microsoft-xdr-auditing" target="_blank" style="color:#58a6ff">xdr-auditing</a></td></tr>
<tr><td>CloudAppEvents</td><td><a href="https://learn.microsoft.com/defender-cloud-apps/ops-guide/ops-guide-ad-hoc" target="_blank" style="color:#58a6ff">ops-guide</a></td></tr>
<tr><td>Custom Roles</td><td><a href="https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles" target="_blank" style="color:#58a6ff">create-roles</a></td></tr>
<tr><td>Graph API</td><td><a href="https://learn.microsoft.com/graph/api/directoryaudit-list" target="_blank" style="color:#58a6ff">directoryaudit</a></td></tr>
</tbody></table>
</div>
</div>
</div></div>

<!-- FOOTER -->
<div class="ft">
<div class="brand">&#x1F6E1;&#xFE0F; <a href="https://github.com/odefender/DefenderXDR-RBAC-Audit" target="_blank">ODEFENDER</a></div>
<div class="brand" style="font-size:12px">Desenvolvido por <a href="https://github.com/odefender" target="_blank">Rafael Franca</a></div>
<div class="sub">Ferramenta open-source para auditoria de permissões do Microsoft Defender XDR<br>MIT License | Gerado em $ts | PowerShell $($PSVersionTable.PSVersion)</div>
</div>

</div></body></html>
"@

# Gravar HTML com UTF-8 (compatível PS 5.1 e 7)
[System.IO.File]::WriteAllText($reportFile, $htmlContent, [System.Text.Encoding]::UTF8)

Write-OK "Relatório: $reportFile"
Start-Process $reportFile

Write-Host "`n============================================" -ForegroundColor Green
Write-Host " AUDITORIA COMPLETA" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host " Workloads:       $aWL/4"
Write-Host " Entra Roles:     $tRA"
Write-Host " Defender RBAC:   $tRB"
Write-Host " Grupos críticos: $($dGrp.Count)"
Write-Host " Eventos:         $tEv"
Write-Host " Relatório:       $reportFile"
Write-Host "============================================" -ForegroundColor Green


