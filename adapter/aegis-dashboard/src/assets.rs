//! Embedded dashboard assets
//!
//! The full HTML/CSS/JS dashboard is embedded in the binary as a static string.
//! Total size target: <50KB.
//!
//! 8 tabs:
//!   1. Overview — "nothing changed, here's what we see" (first screen)
//!   2. Evidence Explorer — receipt chain viewer
//!   3. Vulnerability Scan — vault findings
//!   4. Service Access — per-tool access log
//!   5. Memory Health — memory file integrity
//!   6. SLM Screening — screening verdicts, timing, threat scores
//!   7. Traffic Inspector — request/response inspector with SLM column
//!   8. Emergency Alerts — broadcast messages
//!
//! Refresh: 2s polling via fetch() to /dashboard/api/* endpoints (D12).

/// The full dashboard HTML page, embedded as a compile-time constant.
pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1117;color:#e1e4e8;min-height:100vh}
.header{background:#161b22;border-bottom:1px solid #30363d;padding:12px 24px;display:flex;align-items:center;gap:16px}
.header h1{font-size:18px;font-weight:600;color:#58a6ff}
.mode-badge{padding:4px 10px;border-radius:12px;font-size:12px;font-weight:500}
.mode-observe{background:#1f2d1f;color:#3fb950;border:1px solid #238636}
.mode-enforce{background:#2d1f1f;color:#f85149;border:1px solid #da3633}
.mode-passthrough{background:#2d2a1f;color:#d29922;border:1px solid #9e6a03}
.enforce-banner{background:rgba(245,158,11,0.12);border-bottom:1px solid rgba(245,158,11,0.3);color:#f59e0b;font-size:11px;font-family:monospace;padding:7px 20px;cursor:pointer;position:sticky;top:0;z-index:99}
.enforce-banner:hover{background:rgba(245,158,11,0.18)}
.tabs{display:flex;background:#161b22;border-bottom:1px solid #30363d;padding:0 24px}
.tab{padding:10px 16px;cursor:pointer;font-size:13px;color:#8b949e;border-bottom:2px solid transparent}
.tab:hover{color:#e1e4e8}
.tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
.content{padding:24px;max-width:1200px;margin:0 auto}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;color:#8b949e;margin-bottom:12px;text-transform:uppercase;letter-spacing:0.5px}
.stat{font-size:28px;font-weight:600;color:#e1e4e8}
.stat-label{font-size:12px;color:#8b949e;margin-top:4px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.status-ok{color:#3fb950}
.status-warn{color:#d29922}
.status-error{color:#f85149}
.panel{display:none}.panel.active{display:block}
#loading{text-align:center;padding:40px;color:#8b949e}
table.dtable{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
table.dtable th{text-align:left;padding:8px 10px;color:#8b949e;border-bottom:1px solid #30363d;font-weight:500;font-size:12px;text-transform:uppercase}
table.dtable td{padding:6px 10px;border-bottom:1px solid #21262d;color:#e1e4e8}
table.dtable tr:hover{background:#1c2128}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:500}
.badge-green{background:#1f2d1f;color:#3fb950;border:1px solid #238636}
.badge-red{background:#2d1f1f;color:#f85149;border:1px solid #da3633}
.badge-yellow{background:#2d2a1f;color:#d29922;border:1px solid #9e6a03}
.badge-blue{background:#1f2d3d;color:#58a6ff;border:1px solid #1f6feb}
.badge-gray{background:#21262d;color:#8b949e;border:1px solid #30363d}
.empty-state{color:#8b949e;font-size:13px;padding:16px 0}
.chat-box{max-width:700px;margin:0 auto}
.chat-msg{padding:10px 14px;margin:6px 0;border-radius:12px;font-size:13px;line-height:1.5;max-width:85%;white-space:pre-wrap;word-break:break-word}
.chat-user{background:#1f3d5c;color:#c9d1d9;margin-left:auto;border-bottom-right-radius:4px}
.chat-assistant{background:#1c2128;color:#e1e4e8;border:1px solid #30363d;border-bottom-left-radius:4px}
.chat-system{background:#2d2a1f;color:#d29922;font-size:12px;font-style:italic;border:1px solid #9e6a03;text-align:center;max-width:100%}
.traffic-row{cursor:pointer}
.traffic-row:hover{background:#1c2128 !important}
.body-pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;font-family:monospace;font-size:12px;color:#c9d1d9;overflow-x:auto;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-break:break-word;margin:8px 0}
.detail-back{cursor:pointer;color:#58a6ff;font-size:13px;margin-bottom:12px;display:inline-block}
.detail-back:hover{text-decoration:underline}
.flow-node{padding:8px 14px;border-radius:8px;font-size:12px;font-weight:500;text-align:center;min-width:70px;line-height:1.4}
.flow-arrow{color:#30363d;font-size:18px;padding:0 2px;flex-shrink:0}
.flow-in{background:#1f2d3d;color:#58a6ff;border:1px solid #1f6feb}
.flow-parse{background:#21262d;color:#8b949e;border:1px solid #30363d}
.flow-enrich{background:#2d2a1f;color:#d29922;border:1px solid #9e6a03}
.flow-holster{background:#1f2d1f;color:#3fb950;border:1px solid #238636}
.flow-decision{background:#21262d;color:#e1e4e8;border:2px solid #58a6ff;font-weight:600}
.flow-node-caught{background:#2d1f1f;color:#f85149;border:2px solid #da3633;font-weight:600}
.flow-ms{font-size:10px;color:#8b949e;font-weight:400}
.filter-btn{background:#21262d;color:#8b949e;border:1px solid #30363d;padding:5px 14px;border-radius:16px;font-size:12px;cursor:pointer;font-weight:500}
.filter-btn:hover{background:#30363d;color:#e1e4e8}
.filter-btn.filter-active{background:#1f2d3d;color:#58a6ff;border-color:#1f6feb}
.dim-bar{display:flex;align-items:center;gap:6px;margin:3px 0}
.dim-bar-label{font-size:11px;color:#8b949e;width:80px;text-align:right}
.dim-bar-track{width:120px;height:6px;background:#21262d;border-radius:3px;overflow:hidden}
.dim-bar-fill{height:100%;border-radius:3px}
.dim-bar-val{font-size:10px;color:#8b949e;width:40px}
.timing-bar{display:flex;height:20px;border-radius:4px;overflow:hidden;background:#21262d;margin:8px 0}
.timing-seg{display:flex;align-items:center;justify-content:center;font-size:10px;color:#fff;min-width:20px;white-space:nowrap;padding:0 4px}
.slm-detail-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-top:16px}
.slm-detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:700px){.slm-detail-grid{grid-template-columns:1fr}}
table.dtable .screening-row{cursor:pointer}
table.dtable .screening-row:hover{background:#1c2128}
.trust-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:500}
.trust-full{background:#1f2d1f;color:#3fb950;border:1px solid #238636}
.trust-trusted{background:#1f2d3d;color:#58a6ff;border:1px solid #1f6feb}
.trust-public{background:#2d2a1f;color:#d29922;border:1px solid #9e6a03}
.trust-restricted{background:#2d1f1f;color:#f85149;border:1px solid #da3633}
.trust-unknown{background:#21262d;color:#8b949e;border:1px solid #30363d}
</style>
</head>
<body>
<div class="header">
<h1>Aegis Adapter</h1>
<span class="mode-badge mode-observe" id="mode-badge">observe-only</span>
<span style="flex:1"></span>
<span style="font-size:12px;color:#8b949e" id="version">v0.1.0</span>
</div>
<div id="enforce-banner" class="enforce-banner" style="display:none;" onclick="window.location='/settings#enforcement'"></div>
<div class="tabs">
<div class="tab active" data-tab="overview">Overview</div>
<div class="tab" data-tab="evidence">Evidence</div>
<div class="tab" data-tab="vault">Vault Scan</div>
<div class="tab" data-tab="access">Access</div>
<div class="tab" data-tab="memory">Memory</div>
<div class="tab" data-tab="slm">SLM Screening</div>
<div class="tab" data-tab="traffic">Traffic</div>
<div class="tab" data-tab="alerts">Alerts</div>
</div>
<div class="content">
<div class="panel active" id="panel-overview">
<div class="card">
<h2>Current State</h2>
<p style="color:#3fb950;font-size:16px;margin-bottom:8px">Nothing changed — here's what we see</p>
<p style="color:#8b949e;font-size:13px">The adapter is monitoring your bot. No issues detected.</p>
</div>
<div class="grid">
<div class="card"><div class="stat" id="stat-receipts">0</div><div class="stat-label">Evidence Receipts</div></div>
<div class="card"><div class="stat" id="stat-secrets">0</div><div class="stat-label">Vault Secrets</div></div>
<div class="card"><div class="stat" id="stat-memory">0</div><div class="stat-label">Memory Files</div></div>
<div class="card"><div class="stat status-ok" id="stat-health">Healthy</div><div class="stat-label">System Health</div></div>
</div>
</div>
<div class="panel" id="panel-evidence">
<div class="card"><h2>Evidence Chain</h2>
<div class="grid" id="evidence-stats"></div>
<div id="evidence-table"></div>
</div></div>
<div class="panel" id="panel-vault">
<div class="card"><h2>Credential Vault Scan</h2>
<div id="vault-summary"></div>
<div id="vault-table"></div>
</div></div>
<div class="panel" id="panel-access">
<div class="card"><h2>Service Access Log</h2>
<div id="access-table"></div>
</div></div>
<div class="panel" id="panel-memory">
<div class="card"><h2>Memory Integrity</h2>
<div class="grid" id="memory-stats"></div>
<div id="memory-files"></div>
</div></div>
<div class="panel" id="panel-slm">
<div class="grid" id="slm-stats"></div>
<div class="card"><h2>Screening Log</h2>
<div id="slm-filters" style="display:flex;gap:8px;margin-bottom:12px">
  <button class="filter-btn filter-active" data-filter="all" onclick="slmFilter('all')">All</button>
  <button class="filter-btn" data-filter="admit" onclick="slmFilter('admit')">Admit</button>
  <button class="filter-btn" data-filter="quarantine" onclick="slmFilter('quarantine')">Quarantine</button>
  <button class="filter-btn" data-filter="reject" onclick="slmFilter('reject')">Reject</button>
</div>
<div id="slm-table"></div>
</div>
<div id="slm-detail" style="display:none"></div>
</div>
<div class="panel" id="panel-traffic">
<div class="card"><h2>Traffic Inspector</h2>
<div class="grid" id="traffic-stats"></div>
<div id="traffic-detail" style="display:none;margin-bottom:16px"></div>
<div id="traffic-table"></div>
</div></div>
<div class="panel" id="panel-alerts"><div class="card"><h2>Emergency Alerts</h2><p>No alerts.</p></div></div>
</div>
<script>
let activeTab='overview';
let pageVisible=!document.hidden;
let failCount=0;
document.querySelectorAll('.tab').forEach(t=>{
  t.addEventListener('click',()=>{
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('panel-'+t.dataset.tab).classList.add('active');
    activeTab=t.dataset.tab;
  });
});
document.addEventListener('visibilitychange',()=>{
  pageVisible=!document.hidden;
  if(pageVisible){poll();}
});
const seenAlerts=new Set();
const alertSource=new EventSource('/dashboard/api/alerts/stream');
alertSource.onmessage=(e)=>{
  try{
    const alert=JSON.parse(e.data);
    showAlert(alert);
  }catch{}
};
// alertSource.onerror: EventSource reconnects automatically, no code needed.
// The 5s fallback poll below catches anything missed during reconnect gap.
function showAlert(alert){
  const key=alert.receipt_seq+'_'+alert.ts_ms;
  if(seenAlerts.has(key))return;
  seenAlerts.add(key);
  const panel=document.getElementById('panel-alerts');
  if(!panel)return;
  const card=panel.querySelector('.card');
  if(!card)return;
  const noAlerts=card.querySelector('p');
  if(noAlerts&&noAlerts.textContent==='No alerts.')noAlerts.remove();
  const el=document.createElement('div');
  el.style.cssText='padding:8px;margin-bottom:8px;background:#2d1f1f;border:1px solid #da3633;border-radius:4px;font-size:13px';
  el.textContent='['+new Date(alert.ts_ms).toLocaleTimeString()+'] '+alert.kind+': '+alert.message;
  card.insertBefore(el,card.firstChild);
}
async function fetchAlerts(){
  try{
    const a=await(await fetch('/dashboard/api/alerts')).json();
    if(a.alerts&&a.alerts.length>0){a.alerts.forEach(showAlert);}
  }catch(e){}
}
async function poll(){
  try{
    const s=await(await fetch('/dashboard/api/status')).json();
    document.getElementById('stat-receipts').textContent=s.receipt_count;
    document.getElementById('stat-secrets').textContent=s.vault_secrets;
    document.getElementById('stat-memory').textContent=s.memory_files_tracked;
    document.getElementById('stat-health').textContent=s.health;
    document.getElementById('version').textContent='v'+s.version;
    const badge=document.getElementById('mode-badge');
    badge.textContent=s.mode.replace('_',' ');
    badge.className='mode-badge mode-'+s.mode.split('_')[0];
    const ebanner=document.getElementById('enforce-banner');
    if(s.observe_mode_checks&&s.observe_mode_checks.length>0){
      const names={write_barrier:'Write Barrier',slm_reject:'SLM Screening'};
      const labels=s.observe_mode_checks.map(k=>names[k]||k).join(', ');
      ebanner.textContent='\u26A0 '+labels+' \u2014 warn only, not blocking. Click to enable enforcement.';
      ebanner.style.display='block';
    }else{ebanner.style.display='none';}
    failCount=0;
  }catch(e){
    if(++failCount>=5)document.getElementById('stat-health').textContent='Disconnected';
  }
  if(!pageVisible)return;
  if(activeTab==='evidence'||activeTab==='overview'){
    try{
      const e=await(await fetch('/dashboard/api/evidence')).json();
      document.getElementById('stat-receipts').textContent=e.total_receipts;
      if(activeTab==='evidence'){renderEvidence(e);}
    }catch(e){}
  }
  if(activeTab==='vault'){
    try{
      const v=await(await fetch('/dashboard/api/vault')).json();
      renderVault(v);
    }catch(e){}
  }
  if(activeTab==='access'){
    try{
      const a=await(await fetch('/dashboard/api/access')).json();
      renderAccess(a);
    }catch(e){}
  }
  if(activeTab==='memory'||activeTab==='overview'){
    try{
      const m=await(await fetch('/dashboard/api/memory')).json();
      document.getElementById('stat-memory').textContent=m.tracked_files;
      if(activeTab==='memory'){renderMemory(m);}
    }catch(e){}
  }
  if(activeTab==='slm'){
    try{
      const sl=await(await fetch('/dashboard/api/slm')).json();
      let channelCtx=null;
      try{channelCtx=await(await fetch('/aegis/channel-context')).json();}catch(e){}
      renderSlm(sl,channelCtx);
    }catch(e){}
  }
  if(activeTab==='traffic'){
    try{
      const t=await(await fetch('/dashboard/api/traffic')).json();
      renderTraffic(t);
    }catch(e){}
  }
}
function typeBadge(t){
  const colors={WriteBarrier:'red',MemoryIntegrity:'yellow',ApiCall:'blue',ModeChange:'green',VaultDetection:'red',SlmAnalysis:'yellow',SlmParseFailure:'red'};
  const labels={WriteBarrier:'Write Barrier',MemoryIntegrity:'Memory',ApiCall:'API Call',ModeChange:'Mode',VaultDetection:'Vault',SlmAnalysis:'SLM',SlmParseFailure:'SLM Fail'};
  const c=colors[t]||'gray';
  return '<span class="badge badge-'+c+'">'+(labels[t]||t)+'</span>';
}
function shortHash(h){return h?h.substring(0,12)+'...':'—';}
function fmtTime(ms){return new Date(ms).toLocaleString();}
function fmtTimeShort(ms){return new Date(ms).toLocaleTimeString();}
function esc(s){if(!s)return'—';const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function renderEvidence(e){
  const stats=document.getElementById('evidence-stats');
  const tbl=document.getElementById('evidence-table');
  // Stats cards
  const types={};
  if(e.recent_receipts)e.recent_receipts.forEach(r=>{types[r.receipt_type]=(types[r.receipt_type]||0)+1;});
  let sc='<div class="card"><div class="stat">'+e.total_receipts+'</div><div class="stat-label">Total Receipts</div></div>';
  sc+='<div class="card"><div class="stat">'+e.chain_head_seq+'</div><div class="stat-label">Chain Head Seq</div></div>';
  sc+='<div class="card"><div class="stat" style="font-size:16px">'+(e.last_receipt_ms?fmtTime(e.last_receipt_ms):'—')+'</div><div class="stat-label">Last Receipt</div></div>';
  sc+='<div class="card"><div class="stat">'+Object.keys(types).length+'</div><div class="stat-label">Receipt Types</div></div>';
  stats.innerHTML=sc;
  // Type breakdown
  let typeBreakdown=document.getElementById('evidence-type-breakdown');
  if(!typeBreakdown){typeBreakdown=document.createElement('div');typeBreakdown.id='evidence-type-breakdown';tbl.parentNode.insertBefore(typeBreakdown,tbl);}
  if(Object.keys(types).length>0){
    let tb='<div style="margin:12px 0 16px;display:flex;gap:8px;flex-wrap:wrap">';
    for(const[t,n]of Object.entries(types).sort((a,b)=>b[1]-a[1])){tb+=typeBadge(t)+' <span style="color:#8b949e;font-size:12px;margin-right:8px">'+n+'</span>';}
    tb+='</div>';
    typeBreakdown.innerHTML=tb;
  }else{typeBreakdown.innerHTML='';}
  if(!e.recent_receipts||e.recent_receipts.length===0){tbl.innerHTML='<p class="empty-state">No receipts recorded yet.</p>';return;}
  let h='<table class="dtable"><tr><th>#</th><th>Time</th><th>Type</th><th>Action</th><th>Outcome</th><th>Mode</th><th>Payload Hash</th><th>Prev Hash</th></tr>';
  for(const r of e.recent_receipts){
    h+='<tr>';
    h+='<td>'+r.seq+'</td>';
    h+='<td style="white-space:nowrap">'+fmtTimeShort(r.ts_ms)+'</td>';
    h+='<td>'+typeBadge(r.receipt_type)+'</td>';
    h+='<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(r.action)+'">'+esc(r.action)+'</td>';
    h+='<td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(r.outcome)+'">'+esc(r.outcome)+'</td>';
    h+='<td>'+(r.enforcement_mode?'<span class="badge badge-'+(r.enforcement_mode==='enforce'?'red':'green')+'">'+r.enforcement_mode+'</span>':'—')+'</td>';
    h+='<td style="font-family:monospace;font-size:11px;color:#8b949e" title="'+r.payload_hash+'">'+shortHash(r.payload_hash)+'</td>';
    h+='<td style="font-family:monospace;font-size:11px;color:#8b949e" title="'+r.prev_hash+'">'+shortHash(r.prev_hash)+'</td>';
    h+='</tr>';
  }
  h+='</table>';
  tbl.innerHTML=h;
}
function renderVault(v){
  const sum=document.getElementById('vault-summary');
  const tbl=document.getElementById('vault-table');
  if(v.total_secrets===0){sum.innerHTML='<p class="empty-state">No credentials detected in recent traffic. Vault scans API request and response bodies for leaked secrets (API keys, tokens, passwords) as they pass through the proxy.</p>';tbl.innerHTML='';return;}
  let s='<div class="grid" style="margin-bottom:16px">';
  s+='<div class="card"><div class="stat status-error">'+v.total_secrets+'</div><div class="stat-label">Credentials Detected</div></div>';
  const typeCount=Object.keys(v.by_type).length;
  s+='<div class="card"><div class="stat">'+typeCount+'</div><div class="stat-label">Credential Types</div></div>';
  s+='</div>';
  const types=Object.entries(v.by_type);
  if(types.length>0){s+='<div style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap">';types.forEach(([k,n])=>{s+='<span class="badge badge-red">'+k+'</span> <span style="color:#8b949e;font-size:12px;margin-right:8px">'+n+'</span>';});s+='</div>';}
  sum.innerHTML=s;
  if(!v.recent_findings||v.recent_findings.length===0){tbl.innerHTML='';return;}
  let h='<table class="dtable"><tr><th>Time</th><th>Type</th><th>Masked Preview</th></tr>';
  for(const f of v.recent_findings){
    h+='<tr><td>'+fmtTime(f.detected_at_ms)+'</td><td><span class="badge badge-red">'+f.credential_type+'</span></td><td style="font-family:monospace;font-size:12px">'+esc(f.masked_preview)+'</td></tr>';
  }
  h+='</table>';
  tbl.innerHTML=h;
}
function renderAccess(a){
  const el=document.getElementById('access-table');
  if(!a.entries||a.entries.length===0){el.innerHTML='<p class="empty-state">No API calls recorded yet. Route traffic through Aegis to see entries here.<br><br><span style="font-family:monospace;font-size:12px;color:#58a6ff">export ANTHROPIC_BASE_URL=http://127.0.0.1:3141<br>claude</span></p>';return;}
  let h='<div class="grid" style="margin-bottom:16px"><div class="card"><div class="stat">'+a.total_requests+'</div><div class="stat-label">Total Requests</div></div></div>';
  h+='<table class="dtable"><tr><th>#</th><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Duration</th></tr>';
  for(const e of a.entries){
    const sc=e.status?(e.status<400?'badge-green':'badge-red'):'badge-gray';
    h+='<tr><td>'+e.seq+'</td><td style="white-space:nowrap">'+fmtTimeShort(e.ts_ms)+'</td><td><span class="badge badge-blue">'+e.method+'</span></td><td>'+esc(e.path)+'</td><td><span class="badge '+sc+'">'+(e.status||'—')+'</span></td><td>'+(e.duration_ms?e.duration_ms+'ms':'—')+'</td></tr>';
  }
  h+='</table>';
  el.innerHTML=h;
}
function renderMemory(m){
  const stats=document.getElementById('memory-stats');
  const files=document.getElementById('memory-files');
  // Stats
  let sc='<div class="card"><div class="stat">'+m.tracked_files+'</div><div class="stat-label">Tracked Files</div></div>';
  sc+='<div class="card"><div class="stat'+(m.changes_detected>0?' status-warn':'')+'">'+m.changes_detected+'</div><div class="stat-label">Changes Detected</div></div>';
  sc+='<div class="card"><div class="stat'+(m.unacknowledged_changes>0?' status-error':'')+'">'+m.unacknowledged_changes+'</div><div class="stat-label">Unacknowledged</div></div>';
  sc+='<div class="card"><div class="stat" style="font-size:16px">'+(m.last_scan_ms?fmtTime(m.last_scan_ms):'Never')+'</div><div class="stat-label">Last Scan</div></div>';
  stats.innerHTML=sc;
  // File list
  if(!m.files||m.files.length===0){files.innerHTML='<p class="empty-state">No memory files detected yet. Memory monitor watches MEMORY.md, memory/*.md, HEARTBEAT.md, and USER.md for unauthorized changes.</p>';return;}
  let h='<table class="dtable"><tr><th>File Path</th><th>Last Event</th><th>Verdict</th><th>Last Seen</th></tr>';
  for(const f of m.files){
    const vc=f.verdict==='Clean'?'badge-green':f.verdict==='Blocked'?'badge-red':f.verdict==='Deleted'?'badge-yellow':f.verdict==='Tracked'?'badge-blue':'badge-gray';
    const ec=f.last_event==='changed'?'badge-yellow':f.last_event==='deleted'?'badge-red':f.last_event==='appeared'?'badge-green':f.last_event==='tracked'?'badge-blue':'badge-gray';
    h+='<tr>';
    h+='<td style="font-family:monospace;font-size:12px">'+esc(f.path)+'</td>';
    h+='<td><span class="badge '+ec+'">'+f.last_event+'</span></td>';
    h+='<td><span class="badge '+vc+'">'+f.verdict+'</span></td>';
    h+='<td style="white-space:nowrap">'+fmtTime(f.last_event_ms)+'</td>';
    h+='</tr>';
  }
  h+='</table>';
  files.innerHTML=h;
}
function verdictBadge(v){
  if(v==='reject')return'<span class="badge badge-red">reject</span>';
  if(v==='quarantine')return'<span class="badge badge-yellow">quarantine</span>';
  return'<span class="badge badge-green">admit</span>';
}
function trustBadge(t){
  if(!t)return'';
  return'<span class="trust-badge trust-'+t+'">'+t+'</span>';
}
function threatBar(score){
  const pct=Math.min(100,score/100);
  const color=score>=8000?'#f85149':score>=5000?'#d29922':'#3fb950';
  return'<div style="display:flex;align-items:center;gap:6px"><div style="width:60px;height:6px;background:#21262d;border-radius:3px;overflow:hidden"><div style="width:'+pct+'%;height:100%;background:'+color+'"></div></div><span style="font-size:11px;color:#8b949e">'+score+'</span></div>';
}
let slmData=null;
let slmFilterVal='all';
function slmFilter(f){
  slmFilterVal=f;
  document.querySelectorAll('.filter-btn').forEach(b=>{b.classList.toggle('filter-active',b.dataset.filter===f);});
  if(slmData)renderSlmTable(slmData);
}
function renderSlm(sl,channelCtx){
  slmData=sl;
  const stats=document.getElementById('slm-stats');
  // Channel trust card (if registered)
  let sc='';
  if(channelCtx&&channelCtx.registered){
    sc+='<div class="card" style="grid-column:1/-1"><div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">';
    sc+='<div><div style="font-size:11px;color:#8b949e;margin-bottom:4px">ACTIVE CHANNEL</div>';
    sc+='<span class="badge badge-gray" style="font-size:13px">'+(channelCtx.channel||'unknown')+'</span></div>';
    if(channelCtx.user){sc+='<div><div style="font-size:11px;color:#8b949e;margin-bottom:4px">USER</div><span style="font-size:13px;color:#e1e4e8">'+channelCtx.user+'</span></div>';}
    sc+='<div><div style="font-size:11px;color:#8b949e;margin-bottom:4px">TRUST LEVEL</div>'+trustBadge(channelCtx.trust_level)+'</div>';
    sc+='<div><div style="font-size:11px;color:#8b949e;margin-bottom:4px">SSRF</div><span style="font-size:13px;color:'+(channelCtx.ssrf_allowed?'#3fb950':'#f85149')+'">'+(channelCtx.ssrf_allowed?'allowed':'blocked')+'</span></div>';
    sc+='</div></div>';
  }
  // Stats cards
  sc+='<div class="card"><div class="stat">'+sl.total_screenings+'</div><div class="stat-label">Total Screenings</div></div>';
  const total=sl.total_screenings||1;
  const aPct=Math.round(sl.verdict_counts.admit/total*100);
  const qPct=Math.round(sl.verdict_counts.quarantine/total*100);
  const rPct=Math.round(sl.verdict_counts.reject/total*100);
  sc+='<div class="card"><div style="display:flex;gap:10px;align-items:baseline;flex-wrap:wrap">'+verdictBadge('admit')+' <span class="stat" style="font-size:22px">'+sl.verdict_counts.admit+'</span><span style="font-size:12px;color:#8b949e">('+aPct+'%)</span>'+verdictBadge('quarantine')+' <span class="stat" style="font-size:22px;color:#d29922">'+sl.verdict_counts.quarantine+'</span><span style="font-size:12px;color:#8b949e">('+qPct+'%)</span>'+verdictBadge('reject')+' <span class="stat" style="font-size:22px;color:#f85149">'+sl.verdict_counts.reject+'</span><span style="font-size:12px;color:#8b949e">('+rPct+'%)</span></div>';
  // Stacked verdict bar
  sc+='<div style="display:flex;height:8px;border-radius:4px;overflow:hidden;margin-top:8px;background:#21262d">';
  if(aPct>0)sc+='<div style="width:'+aPct+'%;background:#3fb950"></div>';
  if(qPct>0)sc+='<div style="width:'+qPct+'%;background:#d29922"></div>';
  if(rPct>0)sc+='<div style="width:'+rPct+'%;background:#f85149"></div>';
  sc+='</div><div class="stat-label">Verdict Distribution</div></div>';
  sc+='<div class="card"><div class="stat">'+sl.timing_stats.avg_ms+'<span style="font-size:14px">ms</span></div><div class="stat-label">Avg Screening Time</div></div>';
  sc+='<div class="card"><div class="stat">'+sl.timing_stats.p95_ms+'<span style="font-size:14px">ms</span> <span style="font-size:14px;color:#8b949e">/ '+sl.timing_stats.max_ms+'ms</span></div><div class="stat-label">P95 / Max Latency</div></div>';
  stats.innerHTML=sc;
  renderSlmTable(sl);
}
function renderSlmTable(sl){
  const tbl=document.getElementById('slm-table');
  const detail=document.getElementById('slm-detail');
  if(detail.style.display!=='none')return; // don't overwrite detail view
  if(!sl.recent_screenings||sl.recent_screenings.length===0){tbl.innerHTML='<p class="empty-state">No SLM screenings recorded yet.</p>';return;}
  const filtered=slmFilterVal==='all'?sl.recent_screenings:sl.recent_screenings.filter(e=>e.action===slmFilterVal);
  let h='<table class="dtable"><tr><th>Time</th><th>Verdict</th><th>Threat Score</th><th>Intent</th><th>Channel</th><th>Timing</th><th>Engine</th><th></th></tr>';
  for(const e of filtered){
    h+='<tr class="screening-row" onclick="showSlmDetail('+e.seq+')">';
    h+='<td style="white-space:nowrap">'+fmtTimeShort(e.ts_ms)+'</td>';
    h+='<td>'+verdictBadge(e.action)+'</td>';
    h+='<td>'+threatBar(e.threat_score)+'</td>';
    h+='<td><span class="badge badge-'+(e.intent==='benign'?'green':e.intent==='inject'||e.intent==='exfiltrate'?'red':'yellow')+'">'+e.intent+'</span></td>';
    h+='<td>'+(e.channel_trust_level?trustBadge(e.channel_trust_level):'<span style="color:#30363d;font-size:11px">—</span>')+'</td>';
    // Mini timing breakdown
    h+='<td style="white-space:nowrap"><div class="timing-bar" style="width:100px;height:14px">';
    const tot=e.screening_ms||1;
    const a=e.pass_a_ms||0,b=e.pass_b_ms||0,c=e.classifier_ms||0;
    if(a>0)h+='<div class="timing-seg" style="width:'+Math.max(10,a/tot*100)+'%;background:#d29922" title="Pass A: '+a+'ms"></div>';
    if(b>0)h+='<div class="timing-seg" style="width:'+Math.max(10,b/tot*100)+'%;background:#58a6ff" title="Pass B: '+b+'ms"></div>';
    if(c>0)h+='<div class="timing-seg" style="width:'+Math.max(10,c/tot*100)+'%;background:#3fb950" title="Classifier: '+c+'ms"></div>';
    if(a===0&&b===0&&c===0)h+='<div class="timing-seg" style="width:100%;background:#8b949e" title="Total: '+tot+'ms"></div>';
    h+='</div><span style="font-size:10px;color:#8b949e">'+e.screening_ms+'ms</span></td>';
    h+='<td><span class="badge badge-gray">'+e.engine+'</span></td>';
    h+='<td style="font-size:11px;color:#58a6ff;cursor:pointer">detail →</td>';
    h+='</tr>';
  }
  h+='</table>';
  if(filtered.length===0)h='<p class="empty-state">No '+slmFilterVal+' screenings found.</p>';
  tbl.innerHTML=h;
}
function escHtml(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function layerStatus(detected,label){
  if(detected)return'<div style="display:flex;align-items:center;gap:6px"><span style="color:#f85149;font-size:14px">⛔</span><span style="font-size:12px;color:#f85149;font-weight:600">'+label+' — CAUGHT</span></div>';
  return'<div style="display:flex;align-items:center;gap:6px"><span style="color:#3fb950;font-size:14px">✓</span><span style="font-size:12px;color:#3fb950">'+label+' — clear</span></div>';
}
function showSlmDetail(seq){
  if(!slmData)return;
  const e=slmData.recent_screenings.find(s=>s.seq===seq);
  if(!e)return;
  const detail=document.getElementById('slm-detail');
  // Hide the table card, show the detail view
  const tblCard=document.getElementById('slm-table').parentElement;
  tblCard.style.display='none';
  detail.style.display='block';
  const anns=e.annotations||[];
  const hasPatterns=anns.length>0;
  const isDangerous=e.action==='reject'||e.action==='quarantine';
  let h='<div class="slm-detail-card">';
  h+='<span class="detail-back" onclick="closeSlmDetail()">← Back to screening list</span>';
  h+='<h2 style="font-size:16px;margin:12px 0 16px">Screening #'+e.seq+' — '+verdictBadge(e.action)+' <span style="font-size:13px;color:#8b949e">'+new Date(e.ts_ms).toLocaleString()+'</span></h2>';
  // ── CHANNEL TRUST CONTEXT ──
  if(e.channel||e.channel_trust_level){
    h+='<div style="margin-bottom:16px;padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:6px;display:flex;gap:16px;align-items:center;flex-wrap:wrap">';
    h+='<div style="font-size:11px;color:#8b949e">CHANNEL</div>';
    if(e.channel)h+='<span class="badge badge-gray" style="font-size:12px">'+escHtml(e.channel)+'</span>';
    if(e.channel_user)h+='<span style="font-size:11px;color:#8b949e">user: '+escHtml(e.channel_user)+'</span>';
    if(e.channel_trust_level)h+='<span class="trust-badge trust-'+e.channel_trust_level+'">'+e.channel_trust_level+'</span>';
    h+='</div>';
  }
  // ── SCREENED TEXT ──
  if(e.screened_text){
    h+='<div style="margin-bottom:16px"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">SCREENED TEXT</div>';
    let stxt=escHtml(e.screened_text);
    // Highlight matched excerpts in the text
    if(anns.length>0){for(const ann of anns){const ex=escHtml(ann.excerpt);if(ex&&stxt.includes(ex)){stxt=stxt.replace(ex,'<mark style="background:#5c2d0e;color:#f0883e;padding:1px 2px;border-radius:2px">'+ex+'</mark>');}}}
    h+='<div class="body-pre" style="max-height:150px">'+stxt+'</div></div>';
  }
  // ── REASON BANNER ──
  if(e.reason&&isDangerous){
    h+='<div style="margin-bottom:16px;padding:10px 14px;background:'+(e.action==='reject'?'rgba(248,81,73,0.1);border:1px solid #da3633':'rgba(210,153,34,0.1);border:1px solid #9e6a03')+';border-radius:6px">';
    h+='<div style="font-size:11px;font-weight:600;text-transform:uppercase;margin-bottom:4px;color:'+(e.action==='reject'?'#f85149':'#d29922')+'">'+(e.action==='reject'?'BLOCKED':'QUARANTINED')+'</div>';
    h+='<div style="font-size:13px;color:#e1e4e8">'+escHtml(e.reason)+'</div></div>';
  }
  // ── PIPELINE FLOW (per-entry) — correct order: Heuristic → Classifier → SLM Pass A → SLM Pass B → Holster ──
  h+='<div style="margin-bottom:20px"><div style="font-size:12px;color:#8b949e;margin-bottom:10px">SCREENING PIPELINE</div>';
  h+='<div style="display:flex;flex-wrap:wrap;gap:0;align-items:stretch">';
  const stoppedAt=e.engine; // which layer made the final decision
  // Stage 1: Input
  h+='<div class="flow-node flow-in" style="flex:0 0 auto">Input</div><div class="flow-arrow">→</div>';
  // Stage 2: Heuristic (always runs first, <1ms)
  const heur_caught=stoppedAt==='heuristic';
  h+='<div class="flow-node '+(heur_caught?'flow-node-caught':'flow-holster')+'" style="flex:0 0 auto">';
  h+='Heuristic<br><span class="flow-ms">&lt;1ms</span>';
  if(heur_caught)h+='<br><span style="font-size:10px;color:#f85149;font-weight:600">CAUGHT</span>';
  else h+='<br><span style="font-size:10px;color:#3fb950">clear</span>';
  h+='</div><div class="flow-arrow">→</div>';
  // Stage 3: ProtectAI Classifier
  const cls_ran=e.classifier_ms!=null&&e.classifier_ms>0;
  const cls_caught=stoppedAt==='prompt-guard';
  if(!heur_caught){
    h+='<div class="flow-node '+(cls_caught?'flow-node-caught':cls_ran?'flow-enrich':'flow-parse')+'" style="flex:0 0 auto">';
    h+='Classifier<br><span class="flow-ms">'+(cls_ran?e.classifier_ms+'ms':'~5ms')+'</span>';
    if(cls_caught)h+='<br><span style="font-size:10px;color:#f85149;font-weight:600">CAUGHT</span>';
    else h+='<br><span style="font-size:10px;color:#3fb950">clear</span>';
    h+='</div><div class="flow-arrow">→</div>';
  }
  // Stage 4: SLM Pass A (injection) — only if heuristic+classifier were clean
  const passA_ran=e.pass_a_ms!=null&&e.pass_a_ms>0;
  const passA_caught=anns.some(a=>['DirectInjection','IndirectInjection','PersonaHijack','AuthorityEscalation','EncodingEvasion','BoundaryErosion','MemoryPoison'].includes(a.pattern));
  const passB_ran=e.pass_b_ms!=null&&e.pass_b_ms>0;
  const passB_caught=anns.some(a=>['ExfiltrationAttempt','CredentialProbe','ToolAbuse','LinkInjection'].includes(a.pattern));
  if(!heur_caught&&!cls_caught){
    h+='<div class="flow-node '+(passA_caught?'flow-node-caught':passA_ran?'flow-enrich':'flow-parse')+'" style="flex:0 0 auto">';
    h+='SLM Pass A<br><span class="flow-ms">'+(passA_ran?e.pass_a_ms+'ms':'skipped')+'</span>';
    if(passA_caught)h+='<br><span style="font-size:10px;color:#f85149;font-weight:600">CAUGHT</span>';
    else if(passA_ran)h+='<br><span style="font-size:10px;color:#3fb950">clear</span>';
    h+='</div><div class="flow-arrow">→</div>';
    h+='<div class="flow-node '+(passB_caught?'flow-node-caught':passB_ran?'flow-enrich':'flow-parse')+'" style="flex:0 0 auto">';
    h+='SLM Pass B<br><span class="flow-ms">'+(passB_ran?e.pass_b_ms+'ms':'skipped')+'</span>';
    if(passB_caught)h+='<br><span style="font-size:10px;color:#f85149;font-weight:600">CAUGHT</span>';
    else if(passB_ran)h+='<br><span style="font-size:10px;color:#3fb950">clear</span>';
    h+='</div><div class="flow-arrow">→</div>';
  }
  // Stage 6: Holster / Final Decision
  const holsterColor=e.action==='reject'?'#2d1f1f':e.action==='quarantine'?'#2d2a1f':'#1f2d1f';
  const holsterBorder=e.action==='reject'?'#da3633':e.action==='quarantine'?'#9e6a03':'#238636';
  const holsterText=e.action==='reject'?'#f85149':e.action==='quarantine'?'#d29922':'#3fb950';
  h+='<div class="flow-node" style="flex:0 0 auto;background:'+holsterColor+';color:'+holsterText+';border:2px solid '+holsterBorder+';font-weight:600">';
  h+=(e.holster_profile||'Decision')+'<br><span style="font-size:12px">→ '+e.action.toUpperCase()+'</span>';
  if(e.threshold_exceeded)h+='<br><span style="font-size:10px">threshold exceeded</span>';
  h+='</div>';
  h+='</div></div>';
  // ── LAYER-BY-LAYER BREAKDOWN ──
  h+='<div style="margin-bottom:20px"><div style="font-size:12px;color:#8b949e;margin-bottom:10px">LAYER RESULTS</div>';
  h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">';
  // Layer 1: Heuristic
  h+='<div style="padding:10px 14px;background:#0d1117;border:1px solid '+(heur_caught?'#da3633':'#30363d')+';border-radius:6px">';
  h+='<div style="font-size:11px;font-weight:600;color:#3fb950;margin-bottom:6px">LAYER 1 — Heuristic (regex)</div>';
  if(heur_caught){
    h+='<div style="color:#f85149;font-size:12px;font-weight:600;margin-bottom:4px">CAUGHT — stopped here</div>';
    for(const a of anns)h+='<div style="font-size:11px;margin:2px 0"><span class="badge badge-red" style="font-size:10px">'+escHtml(a.pattern)+'</span> <span style="color:#8b949e">sev:'+a.severity+'</span></div>';
  }else{h+='<div style="color:#3fb950;font-size:12px">Clear — no regex matches</div>';}
  h+='<div style="font-size:10px;color:#8b949e;margin-top:4px">&lt;1ms</div>';
  h+='</div>';
  // Layer 2: ProtectAI Classifier
  h+='<div style="padding:10px 14px;background:#0d1117;border:1px solid '+(cls_caught?'#da3633':'#30363d')+';border-radius:6px">';
  h+='<div style="font-size:11px;font-weight:600;color:#a371f7;margin-bottom:6px">LAYER 2 — ProtectAI Classifier</div>';
  if(heur_caught){h+='<div style="color:#8b949e;font-size:12px">Skipped — heuristic already caught</div>';}
  else if(cls_caught){h+='<div style="color:#f85149;font-size:12px;font-weight:600">CAUGHT — high-confidence MALICIOUS</div>';}
  else{h+='<div style="color:#3fb950;font-size:12px">Clear — classified as safe</div>';}
  h+='<div style="font-size:10px;color:#8b949e;margin-top:4px">'+(cls_ran?e.classifier_ms+'ms':'~5ms')+'</div>';
  h+='</div>';
  // Layer 3: SLM Pass A (injection)
  h+='<div style="padding:10px 14px;background:#0d1117;border:1px solid '+(passA_caught?'#da3633':'#30363d')+';border-radius:6px">';
  h+='<div style="font-size:11px;font-weight:600;color:#d29922;margin-bottom:6px">LAYER 3a — SLM Pass A (injection)</div>';
  if(heur_caught||cls_caught){h+='<div style="color:#8b949e;font-size:12px">Skipped — earlier layer caught</div>';}
  else if(passA_ran){
    const passA_anns=anns.filter(a=>['DirectInjection','IndirectInjection','PersonaHijack','AuthorityEscalation','EncodingEvasion','BoundaryErosion','MemoryPoison'].includes(a.pattern));
    if(passA_anns.length>0){
      h+='<div style="color:#f85149;font-size:12px;font-weight:600;margin-bottom:4px">'+passA_anns.length+' pattern(s) detected</div>';
      for(const a of passA_anns)h+='<div style="font-size:11px;margin:2px 0"><span class="badge badge-red" style="font-size:10px">'+escHtml(a.pattern)+'</span> <span style="color:#8b949e">sev:'+a.severity+'</span></div>';
    }else{h+='<div style="color:#3fb950;font-size:12px">No injection patterns found</div>';}
    h+='<div style="font-size:10px;color:#8b949e;margin-top:4px">'+e.pass_a_ms+'ms</div>';
  }else{h+='<div style="color:#8b949e;font-size:12px">Did not run</div>';}
  h+='</div>';
  // Layer 3: SLM Pass B (recon)
  h+='<div style="padding:10px 14px;background:#0d1117;border:1px solid '+(passB_caught?'#da3633':'#30363d')+';border-radius:6px">';
  h+='<div style="font-size:11px;font-weight:600;color:#58a6ff;margin-bottom:6px">LAYER 3b — SLM Pass B (recon)</div>';
  if(heur_caught||cls_caught){h+='<div style="color:#8b949e;font-size:12px">Skipped — earlier layer caught</div>';}
  else if(passB_ran){
    const passB_anns=anns.filter(a=>['ExfiltrationAttempt','CredentialProbe','ToolAbuse','LinkInjection'].includes(a.pattern));
    if(passB_anns.length>0){
      h+='<div style="color:#f85149;font-size:12px;font-weight:600;margin-bottom:4px">'+passB_anns.length+' pattern(s) detected</div>';
      for(const a of passB_anns)h+='<div style="font-size:11px;margin:2px 0"><span class="badge badge-red" style="font-size:10px">'+escHtml(a.pattern)+'</span> <span style="color:#8b949e">sev:'+a.severity+'</span></div>';
    }else{h+='<div style="color:#3fb950;font-size:12px">No recon patterns found</div>';}
    h+='<div style="font-size:10px;color:#8b949e;margin-top:4px">'+e.pass_b_ms+'ms</div>';
  }else{h+='<div style="color:#8b949e;font-size:12px">Did not run</div>';}
  h+='</div>';
  // Holster decision
  h+='<div style="padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:6px;grid-column:1/-1">';
  h+='<div style="font-size:11px;font-weight:600;color:#e1e4e8;margin-bottom:6px">FINAL DECISION</div>';
  h+='<div style="font-size:13px;font-weight:600;color:'+holsterText+'">'+e.action.toUpperCase()+'</div>';
  if(e.holster_profile)h+='<div style="font-size:11px;color:#8b949e;margin-top:2px">Profile: '+e.holster_profile+'</div>';
  if(e.threshold_exceeded!=null)h+='<div style="font-size:11px;color:#8b949e">Threshold: <span style="color:'+(e.threshold_exceeded?'#f85149':'#3fb950')+'">'+(e.threshold_exceeded?'exceeded':'within limits')+'</span></div>';
  if(e.escalated)h+='<div style="font-size:11px;color:#d29922">Escalated from lower engine</div>';
  h+='</div>';
  // Timing
  h+='<div style="padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:6px">';
  h+='<div style="font-size:11px;font-weight:600;color:#8b949e;margin-bottom:6px">TIMING</div>';
  const tot=e.screening_ms||1;
  h+='<div class="timing-bar" style="height:22px;margin-bottom:6px">';
  const a=e.pass_a_ms||0,b=e.pass_b_ms||0,c=e.classifier_ms||0,oth=Math.max(0,tot-a-b-c);
  if(a>0)h+='<div class="timing-seg" style="width:'+Math.max(8,a/tot*100)+'%;background:#d29922">A:'+a+'ms</div>';
  if(b>0)h+='<div class="timing-seg" style="width:'+Math.max(8,b/tot*100)+'%;background:#58a6ff">B:'+b+'ms</div>';
  if(c>0)h+='<div class="timing-seg" style="width:'+Math.max(8,c/tot*100)+'%;background:#3fb950">C:'+c+'ms</div>';
  if(oth>0&&(a>0||b>0||c>0))h+='<div class="timing-seg" style="width:'+Math.max(8,oth/tot*100)+'%;background:#30363d">'+oth+'ms</div>';
  if(a===0&&b===0&&c===0)h+='<div class="timing-seg" style="width:100%;background:#8b949e">'+tot+'ms</div>';
  h+='</div>';
  h+='<div style="font-size:12px;color:#e1e4e8;font-weight:600">Total: '+e.screening_ms+'ms</div>';
  h+='<div style="font-size:11px;color:#8b949e">Engine: '+e.engine+'</div>';
  h+='</div>';
  h+='</div></div>';
  // ── DETECTED PATTERNS (full detail) ──
  if(anns.length>0){
    h+='<div style="margin-bottom:20px"><div style="font-size:12px;color:#8b949e;margin-bottom:10px">DETECTED PATTERNS ('+anns.length+')</div>';
    for(const ann of anns){
      const sevColor=ann.severity>=8000?'#f85149':ann.severity>=5000?'#d29922':'#58a6ff';
      h+='<div style="padding:10px 14px;background:#0d1117;border-left:3px solid '+sevColor+';border-radius:0 6px 6px 0;margin-bottom:8px">';
      h+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">';
      h+='<span class="badge badge-red">'+escHtml(ann.pattern)+'</span>';
      h+='<span style="font-size:12px;font-weight:600;color:'+sevColor+'">'+ann.severity+' / 10000</span>';
      h+='</div>';
      h+='<div style="font-family:monospace;font-size:12px;color:#f0883e;background:#1c1208;padding:6px 10px;border-radius:4px;overflow-x:auto">"'+escHtml(ann.excerpt)+'"</div>';
      h+='</div>';
    }
    h+='</div>';
  }
  // ── DIMENSIONS ──
  if(e.dimensions){
    h+='<div style="margin-bottom:20px"><div style="font-size:12px;color:#8b949e;margin-bottom:10px">THREAT DIMENSIONS</div>';
    h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 20px">';
    const dims=[['Injection',e.dimensions.injection],['Manipulation',e.dimensions.manipulation],['Exfiltration',e.dimensions.exfiltration],['Persistence',e.dimensions.persistence],['Evasion',e.dimensions.evasion]];
    for(const[name,val] of dims){
      const pct=Math.min(100,val/100);
      const color=val>=8000?'#f85149':val>=5000?'#d29922':val>0?'#58a6ff':'#30363d';
      h+='<div class="dim-bar"><span class="dim-bar-label">'+name+'</span><div class="dim-bar-track"><div class="dim-bar-fill" style="width:'+pct+'%;background:'+color+'"></div></div><span class="dim-bar-val" style="color:'+color+'">'+val+'</span></div>';
    }
    h+='</div></div>';
  }
  // ── SLM EXPLANATION ──
  if(e.explanation){
    h+='<div style="margin-bottom:16px"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">SLM EXPLANATION</div>';
    h+='<div style="font-size:13px;color:#c9d1d9;font-style:italic;padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:6px">'+escHtml(e.explanation)+'</div></div>';
  }
  // ── METADATA ──
  h+='<div style="font-size:11px;color:#30363d;margin-top:8px">seq='+e.seq+' confidence='+e.confidence+' annotations='+e.annotation_count+' engine='+e.engine+'</div>';
  h+='</div>';
  detail.innerHTML=h;
}
function closeSlmDetail(){
  const detail=document.getElementById('slm-detail');
  detail.style.display='none';
  detail.innerHTML='';
  // Show the table card again
  const tblCard=document.getElementById('slm-table').parentElement;
  tblCard.style.display='';
  if(slmData)renderSlmTable(slmData);
}
let trafficDetailId=null;
function renderTraffic(data){
  if(trafficDetailId)return; // don't overwrite detail view
  const stats=document.getElementById('traffic-stats');
  const tbl=document.getElementById('traffic-table');
  let sc='<div class="card"><div class="stat">'+data.total+'</div><div class="stat-label">Captured Requests</div></div>';
  const streaming=data.entries?data.entries.filter(e=>e.is_streaming).length:0;
  sc+='<div class="card"><div class="stat">'+streaming+'</div><div class="stat-label">Streaming (SSE)</div></div>';
  const avgDur=data.entries&&data.entries.length>0?Math.round(data.entries.reduce((s,e)=>s+e.duration_ms,0)/data.entries.length):0;
  sc+='<div class="card"><div class="stat">'+avgDur+'ms</div><div class="stat-label">Avg Latency</div></div>';
  stats.innerHTML=sc;
  if(!data.entries||data.entries.length===0){tbl.innerHTML='<p class="empty-state">No traffic captured yet. Send requests through the proxy to see them here.</p>';return;}
  let h='<table class="dtable"><tr><th>#</th><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>SLM</th><th>Req Size</th><th>Resp Size</th><th>Duration</th><th>Type</th></tr>';
  for(const e of data.entries){
    const sc2=e.status<400?'badge-green':'badge-red';
    h+='<tr class="traffic-row" onclick="showTrafficDetail('+e.id+')">';
    h+='<td>'+e.id+'</td>';
    h+='<td style="white-space:nowrap">'+fmtTimeShort(e.ts_ms)+'</td>';
    h+='<td><span class="badge badge-blue">'+e.method+'</span></td>';
    h+='<td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(e.path)+'</td>';
    h+='<td><span class="badge '+sc2+'">'+e.status+'</span></td>';
    h+='<td>'+(e.slm_verdict?verdictBadge(e.slm_verdict)+' <span style="font-size:11px;color:#8b949e">'+(e.slm_duration_ms||0)+'ms</span>':'<span style="color:#30363d;font-size:11px">—</span>')+'</td>';
    h+='<td>'+fmtBytes(e.request_size)+'</td>';
    h+='<td>'+fmtBytes(e.response_size)+'</td>';
    h+='<td>'+e.duration_ms+'ms</td>';
    h+='<td>'+(e.is_streaming?'<span class="badge badge-yellow">SSE</span>':'<span class="badge badge-gray">REST</span>')+'</td>';
    h+='</tr>';
  }
  h+='</table>';
  tbl.innerHTML=h;
}
function fmtBytes(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB';}
async function showTrafficDetail(id){
  trafficDetailId=id;
  const detail=document.getElementById('traffic-detail');
  const tbl=document.getElementById('traffic-table');
  detail.style.display='block';
  tbl.style.display='none';
  detail.innerHTML='<p style="color:#8b949e">Loading...</p>';
  try{
    const d=await(await fetch('/dashboard/api/traffic/'+id)).json();
    if(d.error){detail.innerHTML='<p class="empty-state">Entry not found (expired from ring buffer).</p>';return;}
    const e=d.entry;
    let h='<span class="detail-back" onclick="closeTrafficDetail()">\u2190 Back to traffic list</span>';
    h+='<div style="display:flex;gap:12px;align-items:center;margin-bottom:16px">';
    h+='<span class="badge badge-blue">'+e.method+'</span>';
    h+='<span style="font-family:monospace;font-size:14px">'+esc(e.path)+'</span>';
    const sc=e.status<400?'badge-green':'badge-red';
    h+='<span class="badge '+sc+'">'+e.status+'</span>';
    h+='<span style="color:#8b949e;font-size:12px">'+e.duration_ms+'ms</span>';
    h+='<span style="color:#8b949e;font-size:12px">'+(e.is_streaming?'streaming':'')+'</span>';
    h+='<span style="color:#8b949e;font-size:12px">'+fmtTime(e.ts_ms)+'</span>';
    if(e.slm_verdict){h+=' '+verdictBadge(e.slm_verdict)+' <span style="font-size:12px;color:#8b949e">score:'+(e.slm_threat_score||0)+' '+(e.slm_duration_ms||0)+'ms</span>';}
    h+='</div>';
    // Chat view if we have parsed messages
    if(d.chat&&d.chat.length>0){
      h+='<h3 style="color:#8b949e;font-size:12px;text-transform:uppercase;margin-bottom:8px">Chat View</h3>';
      h+='<div class="chat-box">';
      for(const m of d.chat){
        const cls=m.role==='user'?'chat-user':m.role==='system'?'chat-system':'chat-assistant';
        h+='<div class="chat-msg '+cls+'"><strong>'+esc(m.role)+'</strong><br>'+esc(m.content)+'</div>';
      }
      h+='</div>';
    }
    // Raw bodies
    h+='<h3 style="color:#8b949e;font-size:12px;text-transform:uppercase;margin:16px 0 8px">Request Body ('+fmtBytes(e.request_size)+')</h3>';
    h+='<div class="body-pre">'+fmtJson(e.request_body)+'</div>';
    h+='<h3 style="color:#8b949e;font-size:12px;text-transform:uppercase;margin:16px 0 8px">Response Body ('+fmtBytes(e.response_size)+')</h3>';
    h+='<div class="body-pre">'+fmtJson(e.response_body)+'</div>';
    detail.innerHTML=h;
  }catch(err){detail.innerHTML='<p class="empty-state">Failed to load detail.</p>';}
}
function closeTrafficDetail(){
  trafficDetailId=null;
  document.getElementById('traffic-detail').style.display='none';
  document.getElementById('traffic-table').style.display='block';
}
function fmtJson(s){
  if(!s)return'(empty)';
  try{return esc(JSON.stringify(JSON.parse(s),null,2));}catch(e){return esc(s);}
}
function schedule(fn,ms){fn().finally(()=>setTimeout(()=>schedule(fn,ms),ms));}
schedule(poll,2000);
schedule(fetchAlerts,5000);
</script>
</body>
</html>"#;
