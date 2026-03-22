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

# Validar módulos necessários — tentar importar, instalar se ausente
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
$svgNodes+="<g transform='translate(10,$sy)' opacity='$op' style='cursor:pointer'><title>$($w.F)`n$stTxt</title><rect width='130' height='36' rx='6' fill='#161b22' stroke='$sc' stroke-width='1.5'/><text x='8' y='15' fill='$sc' font-family='Segoe UI' font-size='9' font-weight='700'>$($w.N)</text><text x='8' y='28' fill='#6e7681' font-family='Segoe UI' font-size='7'>$($w.F)</text>"
$svgNodes+="<circle cx='120' cy='10' r='3.5' fill='$(if($w.A){"#3fb950"}else{"#f85149"})'/></g>`n"
$wlPositions += @{Y=$sy;C=$sc;Op=$op}
$sy+=44}

# Roles/Grupos (direita) - coletar com detalhes para tooltip
$ry = 50; $rightNodes = @()
foreach($rn in ($rd|Where-Object{$_.Name -ne "(vazio)"}|Select-Object -Property Role -Unique).Role){
    $mc=($rd|Where-Object{$_.Role -eq $rn -and $_.Name -ne "(vazio)"}).Count
    $co=if($rC.ContainsKey($rn)){$rC[$rn]}else{"#8b949e"}
    $memberNames=($rd|Where-Object{$_.Role -eq $rn -and $_.Name -ne "(vazio)"}|ForEach-Object{"• $($_.Name) ($($_.Typ))"})-join"`n"
    $rightNodes += @{Y=$ry;N=$rn;C=$co;Cnt=$mc;Type="role";Tip="$rn`n$mc membro(s):`n$memberNames"}
    $ry+=28
}
foreach($g in $dGrp){
    $rbM=$rb|Where-Object{$_.To -eq $g}|Select-Object -First 1
    $gMemberCount=if($rbM.Mb -and $rbM.Mb -ne "(vazio)" -and $rbM.Mb -ne "-"){($rbM.Mb -split ",").Count}else{0}
    $gTip="Grupo RBAC: $g`nRole: $($rbM.CR)`nPermissões: $($rbM.Pm)`nMembros ($gMemberCount): $($rbM.Mb)"
    $rightNodes += @{Y=$ry;N=$g;C="#3fb950";Cnt=$gMemberCount;Type="group";Tip=$gTip}
    $ry+=28
}

# Centro: XDR - calcular APÓS ambos os lados
$centerY = [Math]::Max(60, [Math]::Floor(([Math]::Max($sy, $ry) / 2) - 25))
$svgNodes+="<g style='cursor:pointer'><title>Microsoft Defender XDR`nPortal: security.microsoft.com`nModelo: Unified RBAC`n`nO acesso é controlado por:`n- Entra ID Roles (à direita)`n- Grupos do Unified RBAC (à direita)</title>"
$svgNodes+="<rect x='200' y='$centerY' width='100' height='50' rx='8' fill='#21262d' stroke='#58a6ff' stroke-width='1.5'/>"
$svgNodes+="<text x='250' y='$($centerY+22)' fill='#58a6ff' font-family='Segoe UI' font-size='9' text-anchor='middle' font-weight='700'>DEFENDER XDR</text>"
$svgNodes+="<text x='250' y='$($centerY+37)' fill='#6e7681' font-family='Segoe UI' font-size='7' text-anchor='middle'>Unified RBAC</text></g>`n"

# Linhas workloads → centro
foreach($wp in $wlPositions){
    $svgLines+="<line x1='140' y1='$($wp.Y+18)' x2='200' y2='$($centerY+25)' stroke='$($wp.C)' stroke-width='.8' stroke-dasharray='3' opacity='$($wp.Op)'/>`n"
}

# Nós direita + linhas centro → roles/grupos
foreach($rn in $rightNodes){
    $typeIcon=if($rn.Type -eq "role"){"&#x1F511;"}else{"&#x1F465;"}
    $cntBadge=""
    if($rn.Cnt -gt 0){
        $badgeFill=if($rn.Type -eq "group"){"#3fb950"}else{$rn.C}
        $cntBadge="<rect x='148' y='2' width='20' height='16' rx='8' fill='${badgeFill}25' stroke='$badgeFill' stroke-width='.5'/><text x='158' y='14' fill='$badgeFill' font-family='Segoe UI' font-size='8' text-anchor='middle' font-weight='700'>$($rn.Cnt)</text>"
    }
    # Tooltip com detalhes dos membros
    $tipEscaped = $rn.Tip -replace "'","&#39;"
    $svgNodes+="<g transform='translate(340,$($rn.Y))' style='cursor:pointer'><title>$tipEscaped</title>"
    $svgNodes+="<rect width='170' height='22' rx='4' fill='$($rn.C)08' stroke='$($rn.C)' stroke-width='.8'/>"
    $svgNodes+="<text x='5' y='14' fill='$($rn.C)' font-family='Segoe UI' font-size='7.5' font-weight='600'>$typeIcon $($rn.N)</text>"
    $svgNodes+="$cntBadge</g>`n"
    $svgLines+="<line x1='300' y1='$($centerY+25)' x2='340' y2='$($rn.Y+11)' stroke='$($rn.C)' stroke-width='.6' stroke-dasharray='3' opacity='.3'/>`n"
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

# ── Tabela: Roles → Membros detalhados
$tblDetail=""
foreach($rn in ($rd|Where-Object{$_.Name -ne "(vazio)"}|Select-Object -Property Role -Unique).Role){
    $members=$rd|Where-Object{$_.Role -eq $rn -and $_.Name -ne "(vazio)"}
    foreach($m in $members){
        $bc=switch($m.Typ){"user"{"#1f6feb33;color:#58a6ff"}"group"{"#3fb95033;color:#3fb950"}"servicePrincipal"{"#d2992233;color:#d29922"}default{"#30363d;color:#8b949e"}}
        $co2=if($rC.ContainsKey($rn)){$rC[$rn]}else{"#8b949e"}
        $tblDetail+="<tr><td style='color:$co2;font-weight:600'>$rn</td><td><span style='background:$bc;padding:1px 6px;border-radius:8px;font-size:10px'>$($m.Typ)</span></td><td>$($m.Name)</td><td class='m'>$($m.Id)</td></tr>`n"
    }
}
# Grupos RBAC na mesma tabela
foreach($g in $dGrp){
    $rbMatch=$rb|Where-Object{$_.To -eq $g}|Select-Object -First 1
    $tblDetail+="<tr style='background:#3fb95008'><td style='color:#3fb950;font-weight:600'>RBAC: $($rbMatch.CR)</td><td><span style='background:#3fb95033;color:#3fb950;padding:1px 6px;border-radius:8px;font-size:10px'>grupo</span></td><td>$g</td><td class='m'>Membros: $($rbMatch.Mb)</td></tr>`n"
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
<div class="cd c1"><div class="n">$tRA</div><div class="l">Role Assignments</div></div>
<div class="cd c2"><div class="n">$tRB</div><div class="l">RBAC Custom</div></div>
<div class="cd c3"><div class="n">$tEv</div><div class="l">Eventos</div></div>
<div class="cd c4"><div class="n">$($dGrp.Count)</div><div class="l">Grupos Críticos</div></div>
<div class="cd c5"><div class="n">$aWL/4</div><div class="l">Workloads</div></div>
</div>

<!-- S1: MAPA -->
<div class="sc"><div class="st">&#x1F5FA;&#xFE0F; 1. Mapa de Permissões<a href="$($portal.Perms)" target="_blank">Portal &#x2192;</a></div><div class="sb">
<div class="rt"><b>Por que esta seção existe:</b> O Defender XDR agrega 4 soluções (MDE, MDO, MDI, MDCA) num portal unificado. O acesso é controlado por <b>Entra ID Roles</b> (à direita, com &#x1F511;) e <b>Grupos do Unified RBAC</b> (à direita, com &#x1F465;). À esquerda estão os workloads com status de ativação. O número em cada role indica quantos principals têm acesso. Linhas tracejadas mostram o fluxo: workload → Defender XDR → role/grupo.<br><br>
<b>Como ler:</b> Se um workload está ativo (&#x25CF; verde) mas nenhuma role tem membros, o acesso pode estar vindo de Global Administrator ou de um grupo RBAC.<br>
&#x1F4D6; <a href="https://learn.microsoft.com/defender-xdr/manage-rbac" target="_blank">Ref: Unified RBAC</a></div>
<svg viewBox="0 0 520 $svgH1" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-family:'Segoe UI',sans-serif">
<text x='75' y='35' fill='#6e7681' font-family='Segoe UI' font-size='8' text-anchor='middle' font-weight='600'>WORKLOADS</text>
<text x='250' y='35' fill='#58a6ff' font-family='Segoe UI' font-size='8' text-anchor='middle' font-weight='600'>PORTAL</text>
<text x='425' y='35' fill='#6e7681' font-family='Segoe UI' font-size='8' text-anchor='middle' font-weight='600'>ROLES / GRUPOS</text>
$svg1
</svg></div></div>

<!-- S2: TABELA DETALHADA -->
<div class="sc"><div class="st">&#x1F4CB; 2. Quem tem acesso ao Defender XDR<a href="$($portal.Entra)" target="_blank">Entra ID &#x2192;</a></div><div class="sb">
<div class="rt"><b>Por que esta seção existe:</b> Esta tabela consolida <b>todas</b> as fontes de acesso: Entra ID Roles (atribuição direta) e Grupos do Unified RBAC. Para cada entrada, mostra o tipo de principal (usuário, grupo ou service principal), o nome e o ID mascarado.<br><br>
<b>Achados neste tenant:</b> <b>$nU</b> usuários, <b>$nG</b> grupos e <b>$nS</b> service principals com acesso ao Defender XDR.$(if($nS -gt 2){" &#x26A0;&#xFE0F; <b>$nS service principals com acesso privilegiado</b> - avaliar necessidade."})$(if($dGrp.Count -gt 0){" Grupo(s) no RBAC: <b>$($dGrp -join ', ')</b>."})<br>
&#x1F4D6; <a href="https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference" target="_blank">Ref: Entra ID Roles</a> | <a href="https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles" target="_blank">Custom RBAC</a></div>
<div style="max-height:400px;overflow-y:auto"><table><thead><tr><th>Role / RBAC</th><th>Tipo</th><th>Nome</th><th>ID</th></tr></thead><tbody>
$tblDetail
</tbody></table></div></div></div>

<!-- S3: GRÁFICOS -->
<div class="sc"><div class="st">&#x1F4CA; 3. Análise de Eventos</div><div class="sb">
<div class="rt"><b>Por que esta seção existe:</b> Visualização dos $tEv eventos de alteração de permissão nos últimos $DaysBack dias. O <b>donut</b> mostra a distribuição por tipo - se 100% são grupos, significa que nenhuma role foi alterada diretamente (comum). As <b>barras</b> revelam os top atores - barras <span style="color:#f85149">vermelhas</span> indicam concentração alta (>40% das ações). A <b>timeline</b> mostra picos - barras <span style="color:#f85149">vermelhas</span> são dias com volume anômalo (>70% do máximo).</div>
<div class="gr">
<div><h4 style="color:#6e7681;font-size:11px;margin-bottom:6px">Distribuição por Cenário</h4>
<svg viewBox="0 0 520 200" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-family:'Segoe UI',sans-serif">$svgD</svg></div>
<div><h4 style="color:#6e7681;font-size:11px;margin-bottom:6px">Top Atores (quem mais alterou)</h4>
<svg viewBox="0 0 500 $aH" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-family:'Segoe UI',sans-serif">$svgA</svg></div>
</div>
<h4 style="color:#6e7681;font-size:11px;margin:14px 0 6px">Timeline de Eventos</h4>
<svg viewBox="0 0 780 210" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:6px;border:1px solid #21262d;font-family:'Segoe UI',sans-serif">$svgT</svg>
</div></div>

<!-- S4: EVENTOS -->
<div class="sc"><div class="st">&#x1F50D; 4. Eventos Detalhados (últimos 50)<a href="$($portal.Audit)" target="_blank">Audit Log &#x2192;</a></div><div class="sb">
<div class="rt"><b>Por que esta seção existe:</b> Cada linha é uma alteração de permissão detectada. Borda <span style="color:#f85149">&#x25CF; vermelha</span> = alta severidade (role direta ou RBAC). Borda <span style="color:#d29922">&#x25CF; amarela</span> = média (grupo). Investigue se: (1) QuemFez é conta administrativa esperada, (2) horário é dentro do expediente, (3) IP é de localização conhecida.</div>
$(if($tblEv){"<div style='max-height:350px;overflow-y:auto'><table><thead><tr><th>Timestamp</th><th>Cenário</th><th>Ação</th><th>Quem</th><th>Detalhe</th><th>Alvo</th><th>IP</th></tr></thead><tbody>$tblEv</tbody></table></div>"}else{"<p style='color:#6e7681'>Sem eventos. Execute a query no <a href='$($portal.Hunt)' target='_blank' style='color:#58a6ff'>Advanced Hunting</a>.</p>"})
</div></div>

<!-- S5: KQL LEVANTAMENTO -->
<div class="sc"><div class="st">&#x26A1; 5. KQL - Levantamento<a href="$($portal.Hunt)" target="_blank">Advanced Hunting &#x2192;</a></div><div class="sb">
<div class="rt"><b>Por que esta seção existe:</b> Query que busca <b>todos</b> os eventos de alteração de permissão sem filtros. Use para investigação completa. Une 4 cenários de 2 tabelas: <code>CloudAppEvents</code> (Entra ID cloud) e <code>IdentityDirectoryEvents</code> (AD on-prem).</div>
<button class="cp" onclick="navigator.clipboard.writeText(document.getElementById('k1').textContent).then(()=>{this.textContent='&#x2705;';setTimeout(()=>{this.textContent='Copiar'},2000)})">Copiar</button>
<div class="kql" id="k1">$kH</div></div></div>

<!-- S6: KQL DETECTION RULE -->
<div class="sc"><div class="st">&#x1F6A8; 6. KQL - Detection Rule</div><div class="sb">
<div class="rt"><b>Por que esta seção existe:</b> Versão da query otimizada para criar a <b>Detection Rule</b> que alerta o SOC. $(if($dGrp.Count -gt 0){"Filtra grupos para monitorar apenas: <b>$($dGrp -join ', ')</b> (mapeados via Graph API)."}else{"Sem filtro de grupo - monitora todos."}) Quando disparar, cria um <b>incidente na fila do Defender</b>.</div>
<div class="ins"><h3>Criar a Detection Rule</h3><ol>
<li>Abrir <a href="$($portal.Hunt)" target="_blank" style="color:#58a6ff">Advanced Hunting</a></li>
<li>Copiar a query abaixo e colar</li>
<li><b>Run query</b> para validar</li>
<li><b>Create detection rule</b></li>
<li>Nome: <code>Alteracao Permissoes Defender XDR</code> | Sev: <code>High</code> | Cat: <code>PrivilegeEscalation</code> | Freq: <code>1h</code></li>
<li>Actions: <b>Criar incidente</b></li></ol></div>
<button class="cp" onclick="navigator.clipboard.writeText(document.getElementById('k2').textContent).then(()=>{this.textContent='&#x2705;';setTimeout(()=>{this.textContent='Copiar'},2000)})">Copiar</button>
<div class="kql" id="k2">$kR</div></div></div>

<!-- S7: PERMISSÕES -->
<div class="sc"><div class="st">&#x1F511; 7. Permissões do Script</div><div class="sb">
<div class="rt"><b>Por que esta seção existe:</b> Transparência sobre o que o script precisa para funcionar. Segue o princípio de <b>least privilege</b> - apenas leitura, nenhuma escrita. O script <b>não altera</b> nenhuma configuração no tenant.<br>
&#x1F4D6; <a href="https://learn.microsoft.com/defender-xdr/manage-rbac#permissions-prerequisites" target="_blank">Ref: Prerequisites</a></div>
<table><thead><tr><th>Permissão Graph</th><th>Para quê</th><th>Impacto</th></tr></thead><tbody>
<tr><td>Directory.Read.All</td><td>Ler grupos, usuários, service principals</td><td>Somente leitura</td></tr>
<tr><td>RoleManagement.Read.All</td><td>Ler role assignments (Entra ID + Defender RBAC)</td><td>Somente leitura</td></tr>
<tr><td>ThreatHunting.Read.All</td><td>Executar queries no Advanced Hunting</td><td>Somente leitura</td></tr>
</tbody></table></div></div>

<!-- S8: REFS -->
<div class="sc"><div class="st">&#x1F4DA; 8. Referências</div><div class="sb">
<div class="rt"><b>Por que esta seção existe:</b> Toda decisão técnica é rastreável. ActionTypes, schemas e APIs utilizados estão documentados nas fontes oficiais abaixo.</div>
<table><thead><tr><th>Tema</th><th>URL</th></tr></thead><tbody>
<tr><td>Unified RBAC</td><td><a href="https://learn.microsoft.com/defender-xdr/manage-rbac" target="_blank" style="color:#58a6ff">learn.microsoft.com/defender-xdr/manage-rbac</a></td></tr>
<tr><td>Auditing no Defender XDR</td><td><a href="https://learn.microsoft.com/defender-xdr/microsoft-xdr-auditing" target="_blank" style="color:#58a6ff">learn.microsoft.com/defender-xdr/microsoft-xdr-auditing</a></td></tr>
<tr><td>CloudAppEvents Queries</td><td><a href="https://learn.microsoft.com/defender-cloud-apps/ops-guide/ops-guide-ad-hoc" target="_blank" style="color:#58a6ff">learn.microsoft.com/defender-cloud-apps/ops-guide</a></td></tr>
<tr><td>CloudAppEvents Schema</td><td><a href="https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudappevents-table" target="_blank" style="color:#58a6ff">learn.microsoft.com/.../cloudappevents-table</a></td></tr>
<tr><td>IdentityDirectoryEvents</td><td><a href="https://learn.microsoft.com/defender-xdr/advanced-hunting-identitydirectoryevents-table" target="_blank" style="color:#58a6ff">learn.microsoft.com/.../identitydirectoryevents-table</a></td></tr>
<tr><td>Audit Log Activities</td><td><a href="https://learn.microsoft.com/purview/audit-log-activities" target="_blank" style="color:#58a6ff">learn.microsoft.com/purview/audit-log-activities</a></td></tr>
<tr><td>Graph API Audits</td><td><a href="https://learn.microsoft.com/graph/api/directoryaudit-list" target="_blank" style="color:#58a6ff">learn.microsoft.com/graph/api/directoryaudit-list</a></td></tr>
<tr><td>Custom RBAC Roles</td><td><a href="https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles" target="_blank" style="color:#58a6ff">learn.microsoft.com/.../create-custom-rbac-roles</a></td></tr>
</tbody></table></div></div>

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


