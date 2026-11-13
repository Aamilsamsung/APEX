const $=id=>document.getElementById(id);
const state={tab:'overview',certs:[],findings:[],incidents:[],audit:[],steps:{},selectedCert:null,animatedIncident:null,overview:null,explanations:[],explanationMode:"deterministic-fallback"};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,options={}){const r=await fetch('/api/'+path,{headers:{'Content-Type':'application/json'},...options});const data=await r.json();if(!r.ok)throw new Error(data.detail||'Request failed');return data}
function notice(message,error=false){const n=$('notice');n.textContent=message;n.classList.remove('hidden');n.classList.toggle('error',error);setTimeout(()=>n.classList.add('hidden'),6000)}
async function refresh(){try{const [overview,certs,findings,incidents,audit,explanations]=await Promise.all(['overview','certificates','findings','incidents','audit','explanations'].map(x=>api(x)));const steps=Object.fromEntries(await Promise.all(incidents.map(async i=>[i.id,await api('incidents/'+i.id+'/steps')])));Object.assign(state,{overview,certs,findings,incidents,audit,steps,explanations:explanations.recommendations,explanationMode:explanations.mode});render();renderMap()}catch(e){notice(e.message,true)}}
function renderMap() {
  const select = $('map-service');
  const previous = state.certs.find(cert => cert.id === state.selectedCert);
  const critical = state.findings.find(finding => finding.severity === 'critical');
  const cert = previous || state.certs.find(cert => cert.id === critical?.certificate_id) || state.certs[0];
  select.replaceChildren(...state.certs.map(item => new Option(item.hostname, item.id)));
  select.disabled = !cert;
  if (cert) select.value = cert.id;
  const findings = cert ? state.findings.filter(finding => finding.certificate_id === cert.id) : [];
  window.renderCertificateMap?.(cert, findings);
  $('map-evidence').innerHTML = cert ? `<div><small>Expiration</small><strong>${esc(new Date(cert.expires_at).toLocaleDateString())}</strong></div>
    <div><small>SHA-256 prefix</small><strong><code>${esc(cert.fingerprint)}</code></strong></div>
    <div><small>Finding evidence</small><strong>${esc(findings.map(finding => finding.message).join(' · ') || 'No open findings')}</strong></div>` : '';
}

function incidentEvidence(incident) {
  const evidence = state.steps[incident.id] || {};
  const { before, after } = evidence.comparison || {};
  const deployment = evidence.deployment;
  const deploymentLabel = { verified: 'Live TLS verified', failed: 'Live TLS verification failed', not_running: 'Live TLS check unavailable' }[deployment?.status];
  const compare = before && after ? `<section class="incident-comparison">
    <h4>What changed</h4><div class="comparison-grid">
    ${[before, after].map((cert, index) => `<div><small>${index ? 'Replacement certificate' : 'Original certificate'}</small>
      <dl><dt>Expires</dt><dd>${esc(new Date(cert.expires_at).toLocaleDateString())}</dd>
      <dt>Key</dt><dd>${esc(cert.key_type)} ${esc(cert.key_bits)}</dd>
      <dt>SHA-256 prefix</dt><dd><code>${esc(cert.fingerprint)}</code></dd></dl></div>`).join('')}
    </div>${deploymentLabel ? `<p class="deployment-result ${deployment.status === 'verified' ? 'verified' : ''}">${esc(deploymentLabel)}</p>` : ''}</section>` : '';
  return `<div class="incident-evidence"><div class="incident-steps ${state.animatedIncident === incident.id ? 'replay' : ''}">
    <h4>Incident timeline</h4>
    ${(evidence.steps || []).map((step, index) => `<div class="repair-step" style="--step-delay:${Math.min(index, 8) * 95}ms">
      <span class="repair-number">${index + 1}</span><div><strong>${esc(step.title)}</strong>
      <p>${esc(step.detail)}</p><small>${esc(new Date(step.timestamp).toLocaleString())}</small></div></div>`).join('')}
    </div>${compare}</div>`;
}

function findingHtml(f){const cert=state.certs.find(c=>c.id===f.certificate_id);return `<button class="finding-row" data-certificate="${esc(f.certificate_id)}"><span class="severity-dot ${esc(f.severity)}"></span><div class="grow"><strong>${esc(f.message)}</strong><small>${esc(cert?.hostname||f.certificate_id)} · ${esc(f.code)}</small></div><span class="severity">${esc(f.severity)}</span></button>`}
function render(){const s=state.overview;if(!s)return;$('health').textContent=s.health+'%';$('donut').style.background=`conic-gradient(${s.health>=85?'#55cda2':s.health>=65?'#e6b268':'#ff7987'} ${s.health}%,#26364c 0)`;$('score-status').textContent=s.health>=85?'Good security posture':s.health>=65?'Attention recommended':'Action required';$('total').textContent=s.total;$('healthy').textContent=s.healthy;$('critical').textContent=s.critical;$('warnings').textContent=s.high+s.warnings;$('critical-status').textContent=s.critical?'Review critical findings':'No critical findings';$('top-findings').innerHTML=state.findings.slice(0,5).map(findingHtml).join('')||'<p>No findings detected.</p>';$('finding-list').innerHTML=state.findings.map(findingHtml).join('')||'<p>No findings detected.</p>';$('inventory-rows').innerHTML=state.certs.filter(c=>c.hostname.includes(($('search').value||'').toLowerCase())).map(c=>{const bad=state.findings.some(f=>f.certificate_id===c.id);return `<tr><td>${esc(c.hostname)}</td><td>${esc(c.days_remaining)} days</td><td>${esc(c.key_type)}-${esc(c.key_bits)}</td><td><span class="status ${bad?'bad':''}">${bad?'At risk':'Healthy'}</span></td><td>${esc(c.fingerprint)}…</td></tr>`}).join('');$('explanation-list').innerHTML=`<p class="guide"><strong>Analysis mode:</strong> ${esc(state.explanationMode==='groq-llm'?'Groq LLM (verified findings only)':'Deterministic guidance (LLM not configured or unavailable)')}</p>`+state.explanations.map(g=>`<div class="guide"><strong>${esc(g.finding_id)}</strong><div>${esc(g.explanation)}</div></div>`).join('')||'<p>No guidance needed.</p>';$('incident-list').innerHTML=state.incidents.map(i=>`<div class="incident-card"><h3>${esc(i.type)} <span class="status ${i.status==='resolved'?'':'bad'}">${esc(i.status === 'resolved' ? 'Sandbox rotation complete' : i.status.replaceAll('_',' '))}</span></h3><p>Certificate: ${esc(state.certs.find(c=>c.id===i.certificate_id)?.hostname||state.steps[i.id]?.comparison?.before?.hostname||i.certificate_id)} · ${esc(new Date(i.created_at).toLocaleString())}</p>${i.status==='pending_approval'?`<button class="primary" data-approve="${esc(i.id)}">Approve & remediate</button><button class="secondary" data-reject="${esc(i.id)}">Reject</button>`:''}${i.error?`<p>${esc(i.error)}</p>`:''}${incidentEvidence(i)}</div>`).join('')||'<p>No incidents. Use “Simulate incident” to demonstrate the workflow.</p>';$('audit-list').innerHTML=state.audit.map(a=>`<div class="activity"><div><strong>${esc(a.action)}</strong><div style="color:#7f94ae;margin-top:5px">${esc(a.details)}</div></div><span>${esc(new Date(a.timestamp).toLocaleString())}</span></div>`).join('');$('recent-audit').innerHTML=state.audit.slice(0,3).map(a=>`<div class="activity">${esc(a.action)}<span>${esc(new Date(a.timestamp).toLocaleTimeString())}</span></div>`).join('')}
function tab(name){state.tab=name;document.querySelectorAll('.panel').forEach(e=>e.classList.toggle('active',e.id===name));document.querySelectorAll('.nav').forEach(e=>e.classList.toggle('active',e.dataset.tab===name));const titles={overview:'Security overview',inventory:'Certificate inventory',findings:'Risk findings',incidents:'Incident response',audit:'Audit trail'};$('page-title').textContent=titles[name];$('breadcrumb').textContent=titles[name];document.querySelectorAll('.nav').forEach(e=>e.setAttribute('aria-current',e.dataset.tab===name?'page':'false'));window.scrollTo({top:0})}
async function runScan(){const btn=$('scan');btn.disabled=true;btn.textContent='Scanning certificates…';try{await api('scan',{method:'POST'});await refresh();notice('Scan complete. Findings updated from local certificate files.')}catch(e){notice(e.message,true)}finally{btn.disabled=false;btn.textContent='↻   Run security scan'}}
async function simulate(){const c=state.certs.find(c=>!c.compromised&&!state.incidents.some(i=>i.certificate_id===c.id&&i.status==='pending_approval'));if(!c)return notice('No eligible certificates available',true);if(!confirm(`Simulate a compromised private key for ${c.hostname}? This creates a test incident only.`))return;try{const result=await api('simulate-compromise',{method:'POST',body:JSON.stringify({certificate_id:c.id})});state.animatedIncident=result.incident_id;await refresh();tab('incidents');notice('Simulated compromise created. Human approval is required for remediation.')}catch(e){notice(e.message,true)}}
document.addEventListener('click',async e=>{const nav=e.target.closest('[data-tab],[data-goto]');if(nav)tab(nav.dataset.tab||nav.dataset.goto);const finding=e.target.closest('[data-certificate]');if(finding){state.selectedCert=finding.dataset.certificate;tab('overview');renderMap();$('map-service').focus({preventScroll:true});$('certificate-map').scrollIntoView({block:'center'});}const approve=e.target.closest('[data-approve]');if(approve){const actor=prompt('Enter operator name to explicitly approve sandbox certificate rotation:');if(!actor)return;try{await api(`incidents/${approve.dataset.approve}/approve`,{method:'POST',body:JSON.stringify({approver:actor})});state.animatedIncident=approve.dataset.approve;await refresh();notice('Sandbox rotation complete. See incident evidence for the live TLS check.')}catch(err){notice(err.message,true)}}const reject=e.target.closest('[data-reject]');if(reject){try{await api(`incidents/${reject.dataset.reject}/reject`,{method:'POST'});await refresh();notice('Remediation rejected; compromised certificate remains at risk.')}catch(err){notice(err.message,true)}}});
$('map-service').addEventListener('change', event => {state.selectedCert=event.target.value;renderMap()});$('scan').addEventListener('click',runScan);$('simulate').addEventListener('click',simulate);$('simulate2').addEventListener('click',simulate);$('search').addEventListener('input',render);$('clock').textContent=new Date().toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});refresh();
// Extended sandbox diagnostics. Results are never presented as live internet scans.
async function showDiagnostics(){
  try {
    const [ct,chain]=await Promise.all([api('ct-monitor'),api('audit-integrity')]);
    let section=$('sandbox-diagnostics');
    if(!section){section=document.createElement('section');section.id='sandbox-diagnostics';section.className='guide';document.querySelector('#overview')?.appendChild(section)}
    section.innerHTML=`<h3>Sandbox integrity & mock CT monitoring</h3><p>Audit chain: <strong>${chain.valid?'Verified':'FAILED'}</strong> (${chain.entries??0} chained events)</p><p>CT replay: ${ct.map(x=>`${esc(x.hostname)} — ${esc(x.status)}`).join(' · ')}</p><button id="check-live-tls" class="secondary">Check local TLS server</button><p id="live-tls-result">Start the optional TLS server to test actual deployment.</p>`;
    $('check-live-tls').onclick=async()=>{try{const r=await api('scan-local-tls',{method:'POST'});$('live-tls-result').textContent=`Served serial ${r.serial}; CA verified: ${r.chain_valid}; hostname verified: ${r.hostname_valid}; revoked: ${r.revoked}`}catch(e){$('live-tls-result').textContent='Local TLS server unavailable: '+e.message}}
  }catch(e){notice('Diagnostics: '+e.message,true)}
}
showDiagnostics();
