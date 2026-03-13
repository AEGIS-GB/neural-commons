//! Embedded dashboard assets
//!
//! The full HTML/CSS/JS dashboard is embedded in the binary as a static string.
//! Total size target: <50KB.
//!
//! 6 tabs:
//!   1. Overview — "nothing changed, here's what we see" (first screen)
//!   2. Evidence Explorer — receipt chain viewer
//!   3. Vulnerability Scan — vault findings
//!   4. Service Access — per-tool access log
//!   5. Memory Health — memory file integrity
//!   6. Emergency Alerts — broadcast messages
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
  let h='<table class="dtable"><tr><th>#</th><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Req Size</th><th>Resp Size</th><th>Duration</th><th>Type</th></tr>';
  for(const e of data.entries){
    const sc2=e.status<400?'badge-green':'badge-red';
    h+='<tr class="traffic-row" onclick="showTrafficDetail('+e.id+')">';
    h+='<td>'+e.id+'</td>';
    h+='<td style="white-space:nowrap">'+fmtTimeShort(e.ts_ms)+'</td>';
    h+='<td><span class="badge badge-blue">'+e.method+'</span></td>';
    h+='<td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(e.path)+'</td>';
    h+='<td><span class="badge '+sc2+'">'+e.status+'</span></td>';
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
