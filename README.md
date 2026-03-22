<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell" alt="PowerShell">
  <img src="https://img.shields.io/badge/PowerShell-7%2B-blue?logo=powershell" alt="PowerShell 7">
  <img src="https://img.shields.io/badge/Microsoft%20Graph-SDK-orange?logo=microsoft" alt="Graph SDK">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT">
  <img src="https://img.shields.io/badge/Defender%20XDR-Unified%20RBAC-purple?logo=microsoft" alt="Defender XDR">
</p>

<h1 align="center">🛡️ Defender XDR RBAC Audit</h1>

<p align="center">
  <strong>Auditoria automatizada de permissões do Microsoft Defender XDR</strong><br>
  Mapeia roles, grupos, workloads e eventos de alteração de acesso — gera relatório HTML interativo
</p>

<p align="center">
  <a href="https://github.com/odefender">ODEFENDER Community</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#o-problema">O Problema</a> •
  <a href="#como-funciona">Como Funciona</a> •
  <a href="#relatório">Relatório</a>
</p>

---

## 🎯 O Problema

> *"Quem criou ou alterou perfis de acesso no portal do Defender XDR? E como o SOC pode ser alertado quando isso acontecer?"*

O acesso ao Microsoft Defender XDR é controlado por **múltiplas fontes** — e a maioria das organizações não monitora todas:

| Caminho de Acesso | Como funciona | Risco se não monitorado |
|---|---|---|
| **Entra ID Roles** | Usuário recebe "Security Administrator" diretamente | Escalação de privilégio não detectada |
| **Grupos de Segurança** | Usuário é adicionado a grupo com role ou RBAC associado | Acesso indireto não rastreado |
| **Unified RBAC Custom Roles** | Admin cria role com permissões granulares no Defender | Shadow admin não visível |
| **Grupos AD on-prem** | Grupo sincronizado via Entra Connect concede acesso | Bypass do controle cloud |

**Este script resolve o problema de ponta a ponta** — do mapeamento à detecção automatizada.

## 🚀 Quick Start

```powershell
# 1. Clonar
git clone https://github.com/odefender/DefenderXDR-RBAC-Audit.git
cd DefenderXDR-RBAC-Audit

# 2. Executar (módulos serão instalados automaticamente se necessário)
.\Audit-DefenderXDR-RBAC.ps1

# 3. O relatório HTML abre automaticamente no browser
```

Na primeira execução, será solicitado autenticação via **device code** — um código para entrar em `microsoft.com/devicelogin`. Funciona em qualquer terminal, incluindo Azure Cloud Shell.

## 📋 Como Funciona

```
┌─────────────────────────────────────────────────────────────┐
│                    Audit-DefenderXDR-RBAC.ps1                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Autenticar (Microsoft Graph API - device code)           │
│     ↓                                                        │
│  2. Detectar workloads ativos (MDE, MDO, MDI, MDCA)          │
│     ↓                                                        │
│  3. Mapear Entra ID Roles → quem tem cada role               │
│     ↓                                                        │
│  4. Mapear Unified RBAC → custom roles + grupos associados   │
│     ↓                                                        │
│  5. Construir query KQL (dinâmica, com grupos mapeados)      │
│     ↓                                                        │
│  6. Executar no Advanced Hunting → coletar eventos           │
│     ↓                                                        │
│  7. Gerar relatório HTML interativo                          │
│     • SVG: Mapa de permissões (workloads ↔ roles ↔ grupos)   │
│     • Gráficos: Donut, timeline, top atores                  │
│     • Tabelas: Acesso detalhado, eventos com severidade      │
│     • KQL: Pronta para copiar e criar Detection Rule         │
│     ↓                                                        │
│  8. Abrir no browser                                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### O que é coletado automaticamente

| Dado | Fonte | API |
|---|---|---|
| Workloads ativos | Advanced Hunting tables | `runHuntingQuery` |
| Entra ID Roles | `roleManagement/directory` | Graph v1.0 |
| Role assignments | `roleAssignments` | Graph v1.0 |
| Principals (users, groups, SPs) | `directoryObjects` | Graph v1.0 |
| Defender RBAC custom roles | `roleManagement/defender` | Graph beta |
| RBAC role assignments | `roleManagement/defender/roleAssignments` | Graph beta |
| Group members | `groups/{id}/members` | Graph v1.0 |
| Alteração de permissões | `CloudAppEvents` | KQL |
| Alteração de grupo AD | `IdentityDirectoryEvents` | KQL |

**Nenhuma informação é hardcoded** — tudo é dinâmico e adaptado ao tenant.

## 📊 Relatório

O relatório HTML gerado inclui:

### 1. Mapa de Permissões (SVG interativo)
- **Esquerda**: Workloads com status (ativo/inativo)
- **Centro**: Hub Defender XDR
- **Direita**: Roles e grupos com contagem de membros
- **Tooltips**: Passe o mouse para ver membros e permissões detalhadas

### 2. Tabela "Quem tem acesso"
- Todas as Entra ID Roles com seus principals
- Grupos do Unified RBAC com membros
- Badges coloridos por tipo (user, group, servicePrincipal)
- Alertas automáticos para service principals com acesso privilegiado

### 3. Gráficos de Eventos
- **Donut**: Distribuição por cenário (role, grupo, RBAC, AD)
- **Top Atores**: Quem mais alterou permissões (com cores por concentração)
- **Timeline**: Picos diários (cores por volume anômalo)

### 4. Eventos Detalhados
- Tabela scrollável com severidade visual
- Vermelho = alteração de role/RBAC (alto impacto)
- Amarelo = alteração de grupo (médio impacto)

### 5-6. Queries KQL
- **Levantamento**: Query completa sem filtros
- **Detection Rule**: Query filtrada com grupos do RBAC
- Botão de copiar → colar direto no Advanced Hunting
- Passo a passo para criar a Detection Rule

## 🔔 Cenários Monitorados (KQL)

| # | Cenário | Tabela | ActionType |
|---|---------|--------|------------|
| 1 | Atribuição/remoção de Entra ID Role | `CloudAppEvents` | `Add member to role.` / `Remove member from role.` |
| 2 | Alteração de membership em grupo | `CloudAppEvents` | `Add member to group.` / `Remove member from group.` |
| 3 | Criação/edição/exclusão de custom role | `CloudAppEvents` | `AddRole` / `EditRole` / `DeleteRole` |
| 4 | Alteração de grupo no AD on-prem | `IdentityDirectoryEvents` | `Group Membership changed` |

## 🔐 Permissões Necessárias

| Permissão Graph | Finalidade | Tipo |
|---|---|---|
| `Directory.Read.All` | Ler grupos, usuários, service principals | Somente leitura |
| `RoleManagement.Read.All` | Ler role assignments (Entra ID + Defender) | Somente leitura |
| `ThreatHunting.Read.All` | Executar queries no Advanced Hunting | Somente leitura |

**O script não altera nenhuma configuração no tenant.**

O usuário que executa precisa ter pelo menos **Security Reader** no Entra ID.
Para criar Detection Rules no portal, é necessário **Security Administrator**.

## 💻 Compatibilidade

| Ambiente | Status |
|---|---|
| PowerShell 5.1 (Windows) | ✅ Testado |
| PowerShell 7+ (cross-platform) | ✅ Testado |
| Azure Cloud Shell | ✅ Compatível (device code auth) |
| Microsoft Graph SDK 2.x | ✅ Auto-instalação se ausente |

## 📖 Uso Avançado

```powershell
# Últimos 90 dias
.\Audit-DefenderXDR-RBAC.ps1 -DaysBack 90

# Salvar em pasta específica
.\Audit-DefenderXDR-RBAC.ps1 -OutputPath "C:\Reports"

# Combinado
.\Audit-DefenderXDR-RBAC.ps1 -DaysBack 60 -OutputPath "\\server\share\reports"
```

## 📚 Referências Oficiais

| Tema | URL |
|---|---|
| Unified RBAC | [learn.microsoft.com/defender-xdr/manage-rbac](https://learn.microsoft.com/defender-xdr/manage-rbac) |
| Defender XDR Auditing | [learn.microsoft.com/defender-xdr/microsoft-xdr-auditing](https://learn.microsoft.com/defender-xdr/microsoft-xdr-auditing) |
| CloudAppEvents Queries | [learn.microsoft.com/defender-cloud-apps/ops-guide](https://learn.microsoft.com/defender-cloud-apps/ops-guide/ops-guide-ad-hoc) |
| CloudAppEvents Schema | [learn.microsoft.com/.../cloudappevents-table](https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudappevents-table) |
| IdentityDirectoryEvents | [learn.microsoft.com/.../identitydirectoryevents-table](https://learn.microsoft.com/defender-xdr/advanced-hunting-identitydirectoryevents-table) |
| Audit Log Activities | [learn.microsoft.com/purview/audit-log-activities](https://learn.microsoft.com/purview/audit-log-activities) |
| Graph API Audits | [learn.microsoft.com/graph/api/directoryaudit-list](https://learn.microsoft.com/graph/api/directoryaudit-list) |
| Custom RBAC Roles | [learn.microsoft.com/.../create-custom-rbac-roles](https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles) |

## 🤝 Comunidade ODEFENDER

Este projeto faz parte da comunidade **ODEFENDER** — focada em segurança ofensiva e defensiva com tecnologias Microsoft.

- 🌐 [GitHub: github.com/odefender](https://github.com/odefender)
- 💬 Contribuições são bem-vindas — abra uma Issue ou Pull Request
- 📧 Dúvidas e sugestões: abra uma [Discussion](https://github.com/odefender/DefenderXDR-RBAC-Audit/discussions)

### Como contribuir

1. Fork o repositório
2. Crie uma branch (`git checkout -b feature/minha-melhoria`)
3. Commit suas mudanças (`git commit -m 'Add: minha melhoria'`)
4. Push para a branch (`git push origin feature/minha-melhoria`)
5. Abra um Pull Request

### Ideias para contribuição

- [ ] Suporte a PIM (Privileged Identity Management) — ativações temporárias
- [ ] Export para PDF
- [ ] Integração com Sentinel Analytics Rules
- [ ] Dashboard web com histórico de execuções
- [ ] Modo dark/light toggle no report
- [ ] Notificação via Teams webhook ao detectar alteração

## 📜 Licença

MIT — Use, modifique e distribua livremente.

---

<p align="center">
  <strong>🛡️ Desenvolvido por <a href="https://github.com/odefender">Rafael Franca</a> — ODEFENDER</strong><br>
  <em>Segurança não é produto, é processo.</em>
</p>
