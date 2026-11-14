const $=id=>document.getElementById(id);
const state={tab:'overview',certs:[],findings:[],incidents:[],audit:[],steps:{},selectedCert:null,animatedIncident:null,overview:null,explanations:[],explanationMode:"deterministic-fallback"};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// Browser-session-only previews: never mix user-declared metadata with verified X.509 inventory.
let unverifiedImports=[];
try { const saved=JSON.parse(sessionStorage.getItem('apex_unverified_imports')||'[]');if(Array.isArray(saved))unverifiedImports=saved.slice(0,100); } catch {}
function renderUnverifiedImports(){
  const body=$('unverified-metadata-rows'),empty=$('unverified-metadata-empty');
  if(!body)return;
  const query=($('search')?.value||'').toLowerCase();
  const rows=unverifiedImports.filter(r=>String(r.hostname).toLowerCase().includes(query));
  body.innerHTML=rows.map(r=>{const risks=Array.isArray(r.risks)?r.risks:[];const status=risks.length?'<span class="status bad" title="Risk based on declared metadata only">At risk · '+risks.length+' finding'+(risks.length===1?'':'s')+'</span>':'<span class="status" style="color:#9bd8b8;border:1px solid #47745d;background:#17362a" title="No risks found in declared fields; certificate not verified">No declared risks</span>';return '<tr><td>'+esc(r.hostname)+'</td><td>'+esc(r.days_remaining==null?'Not provided':r.days_remaining+' days')+'</td><td>'+esc(r.issuer||'Not provided')+'</td><td>'+status+'</td><td>'+esc(risks.length?risks.join(', '):'None declared')+'</td><td><span class="status bad">Unverified metadata</span></td></tr>';}).join('');
  if(empty)empty.hidden=unverifiedImports.length>0;
}
async function api(path,options={}){
  const mutation=(options.method||'GET').toUpperCase()!=='GET';
  let token=sessionStorage.getItem('aegis_operator_token')||'';
  const publicDemo=path==='certificates/import-metadata';
  if(mutation&&!publicDemo&&!token){
    token=prompt('Operator access token (provided by the APEX demo owner):')||'';
    if(!token)throw new Error('Operator authorization required');
    sessionStorage.setItem('aegis_operator_token',token);
  }
  const headers={'Content-Type':'application/json',...(options.headers||{})};
  if(mutation&&token)headers['X-Aegis-Operator-Token']=token;
  const r=await fetch('/api/'+path,{...options,headers});
  let data;try{data=await r.json()}catch{data={detail:'Unexpected server response'}}
  if(r.status===401){sessionStorage.removeItem('aegis_operator_token');throw new Error('Invalid operator token. Please retry the action.')}
  if(!r.ok)throw new Error(data.detail||'Request failed');
  return data;
}
function notice(message,error=false){const n=$('notice');n.textContent=message;n.classList.remove('hidden');n.classList.toggle('error',error);setTimeout(()=>n.classList.add('hidden'),6000)}
async function refresh(){try{const [overview,certs,findings,incidents,audit,explanations,healthHistory,localRecoveryEvidence]=await Promise.all(['overview','certificates','findings','incidents','audit','explanations','health-history','local-recovery/evidence'].map(x=>x==='local-recovery/evidence'?api(x).catch(()=>({available:false})):api(x)));const steps=Object.fromEntries(await Promise.all(incidents.map(async i=>[i.id,await api('incidents/'+i.id+'/steps')])));Object.assign(state,{overview,certs,findings,incidents,audit,steps,explanations:explanations.recommendations,explanationMode:explanations.mode,explanationReason:explanations.reason,explanationNote:explanations.note,explanationHint:explanations.provider_hint,healthHistory,localRecoveryEvidence});render();renderMap()}catch(e){notice(e.message,true)}}
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
let healthTarget;
let displayedHealth = 0;
let healthFrame;

function animateHealth(target) {
  if (target === healthTarget) return;
  healthTarget = target;
  cancelAnimationFrame(healthFrame);
  $('health-gauge').setAttribute('aria-label', `Certificate health ${target}%`);
  $('health-gauge').dataset.level = target >= 85 ? 'good' : target >= 65 ? 'review' : 'attention';

  function draw(value) {
    displayedHealth = value;
    $('health').textContent = Math.round(value);
    $('health-fill').style.strokeDashoffset = 100 - value;
  }

  if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
    draw(target);
    return;
  }

  const from = displayedHealth;
  const started = performance.now();
  draw(from);
  function tick(now) {
    const progress = Math.min((now - started) / 950, 1);
    const eased = 1 - (1 - progress) ** 3;
    draw(from + (target - from) * eased);
    if (progress < 1) healthFrame = requestAnimationFrame(tick);
  }
  healthFrame = requestAnimationFrame(tick);
}

function renderRecoveryEvidence(){
  const el=$('local-recovery-evidence');if(!el)return;
  const record=state.localRecoveryEvidence;
  if(!record?.available){el.textContent='No operator-attested real CA recovery recorded on this server. Local demo results are not automatically synchronized.';return;}
  const e=record.evidence;
  el.innerHTML='<p><strong>Operator-attested (not independently cloud-verified)</strong> · '+esc(record.timestamp)+'</p><p>Service: '+esc(e.hostname)+' · Replacement serial: <code>'+esc(e.new_serial)+'</code></p><p>Deployment verification: '+(e.deployment_verified?'reported PASS':'not confirmed')+' · Old certificate revocation: '+(e.ca_revocation_confirmed?'reported confirmed':'not confirmed')+'</p><p style="font-size:12px;opacity:.7">Fingerprint: <code>'+esc(e.sha256_fingerprint)+'</code></p>';
}
function renderHealthTrend(){
  const history=state.healthHistory||[];
  const el=$('health-trend'), count=$('trend-count');
  if(!el||!count)return;
  count.textContent=history.length+' recorded scan'+(history.length===1?'':'s');
  if(!history.length){el.textContent='No historical scores yet. Run a scan to begin tracking.';return;}
  const width=800,height=110,pad=12;
  const coords=history.map((entry,i)=>({
    x:pad+(history.length===1?0.5:i/(history.length-1))*(width-2*pad),
    y:pad+(100-entry.health)/100*(height-2*pad)
  }));
  const points=coords.map(p=>p.x.toFixed(1)+','+p.y.toFixed(1)).join(' ');
  const first=history[0],last=history[history.length-1];
  el.innerHTML='<svg viewBox="0 0 800 110" role="img" aria-label="Health score history from '+history.length+' recorded scans" style="width:100%;height:110px"><line x1="12" y1="12" x2="788" y2="12" stroke="currentColor" opacity=".1"/><line x1="12" y1="98" x2="788" y2="98" stroke="currentColor" opacity=".1"/><polyline fill="none" stroke="#31a87d" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" points="'+points+'"/></svg><div style="display:flex;justify-content:space-between;gap:12px;font-size:12px;opacity:.75"><span>First recorded: '+esc(first.health)+'%</span><span>Latest: '+esc(last.health)+'%</span></div>';
}
function render(){const s=state.overview;if(!s)return;const llm=$('llm-status');if(llm){const live=['groq-llm','gemini-llm'].includes(state.explanationMode);const noFindings=state.explanationMode==='no-findings';llm.textContent=live?'● AI Risk Analyst active — AI-generated explanations':noFindings?'● No findings to analyze — Groq not tested':'● Fallback active — rule-based explanations';llm.style.color=live?'#38b991':'#e6ad55';const detail=$('llm-status-detail');if(detail)detail.textContent=live?'AI model returned explanations grounded in detected findings.':state.explanationNote+(state.explanationReason?' Reason: '+state.explanationReason.replaceAll('_',' '):'')+(state.explanationHint?' · '+state.explanationHint.replaceAll('_',' '):'');}renderHealthTrend();renderRecoveryEvidence();animateHealth(s.health);$('score-status').textContent=s.health>=85?'Good standing':s.health>=65?'Review recommended':'Needs attention';$('total').textContent=s.total;$('healthy').textContent=s.healthy;$('critical').textContent=s.critical;$('warnings').textContent=s.high+s.warnings;$('critical-status').textContent=s.critical?'Review critical findings':'No critical findings';$('top-findings').innerHTML=state.findings.slice(0,5).map(findingHtml).join('')||'<p>No findings detected.</p>';$('finding-list').innerHTML=state.findings.map(findingHtml).join('')||'<p>No findings detected.</p>';$('inventory-rows').innerHTML=state.certs.filter(c=>c.hostname.includes(($('search').value||'').toLowerCase())).map(c=>{const bad=state.findings.some(f=>f.certificate_id===c.id);return `<tr data-open-cert="${esc(c.id)}" style="cursor:pointer" title="Click to review certificate and renewal options"><td>${esc(c.hostname)}</td><td>${esc(c.days_remaining)} days</td><td>${esc(c.key_type)}-${esc(c.key_bits)}</td><td><span class="status ${bad?'bad':''}">${bad?'At risk':'Healthy'}</span></td><td>${esc(c.fingerprint)}…</td></tr>`}).join('');renderUnverifiedImports();$('explanation-list').innerHTML=`<p class="guide"><strong>Analysis mode:</strong> ${esc(['groq-llm','gemini-llm'].includes(state.explanationMode)?'AI LLM (verified findings only)':'Deterministic guidance (LLM not configured or unavailable)')}</p>`+state.explanations.map(g=>`<div class="guide"><strong>${esc(g.finding_id)}</strong><div>${esc(g.explanation)}</div></div>`).join('')||'<p>No guidance needed.</p>';$('incident-list').innerHTML=state.incidents.map(i=>`<div class="incident-card" data-incident-id="${esc(i.id)}"><h3>${esc(i.type)} <span class="status ${i.status==='resolved'?'':'bad'}">${esc(i.status === 'resolved' ? 'Sandbox rotation complete' : i.status.replaceAll('_',' '))}</span></h3><p>Certificate: ${esc(state.certs.find(c=>c.id===i.certificate_id)?.hostname||state.steps[i.id]?.comparison?.before?.hostname||i.certificate_id)} · ${esc(new Date(i.created_at).toLocaleString())}</p>${i.status==='pending_approval'?`<button class="primary" data-approve="${esc(i.id)}">Approve & remediate</button><button class="secondary" data-reject="${esc(i.id)}">Reject</button>`:''}${i.error?`<p>${esc(i.error)}</p>`:''}${incidentEvidence(i)}</div>`).join('')||'<p>No incidents. Use “Simulate incident” to demonstrate the workflow.</p>';$('audit-list').innerHTML=state.audit.map(renderAuditEntry).join('');$('recent-audit').innerHTML=state.audit.slice(0,3).map(a=>`<div class="activity">${esc(a.action)}<span>${esc(new Date(a.timestamp).toLocaleTimeString())}</span></div>`).join('')}
function auditDescription(action, data) {
  const names={
    'scan.completed':['Security scan completed','The scanner checked registered sandbox certificates for risks.'],
    'agent.responder.completed':['Response agent finished','The responder finished its assigned sandbox remediation workflow.'],
    'remediation.completed':['Sandbox recovery completed','The sandbox CA rotated the certificate and recorded the outcome. This is not an ACME operation.'],
    'remediation.revoked':['Old certificate revoked in sandbox','The sandbox CA revocation registry was updated for the old certificate.'],
    'remediation.deployment_verified':['Replacement verified on local TLS demo','The loopback TLS demonstration endpoint presented the replacement certificate.'],
    'remediation.notification_result':['Notification integration checked','The system recorded whether the external notification channel was available.'],
    'notification_delivery':['Notification delivery status','The notification service reported its delivery or configuration status.'],
    'remediation.local_acme_approved':['Local ACME operation approved','An operator authorized a restricted local worker job; approval does not mean execution succeeded.'],
    'remediation.local_acme_result':['Local ACME worker reported','Certificate issuance result was reported. Revocation and deployment require separate verification.'],
    'worker.job.completed':['Local worker job finished','The authenticated worker returned a result for its assigned job.']
  };
  const known=names[action]||[action.replaceAll(/[._]/g,' ').replace(/\b\w/g,x=>x.toUpperCase()),'A backend security event was recorded. Open technical details for the evidence.'];
  let extra='';
  if(data.status==='not_configured')extra=' External webhook notifications are not configured.';
  if(data.scope)extra+=' Scope: '+data.scope+'.';
  if(data.certificates!=null)extra+=' Certificates scanned: '+data.certificates+'.';
  if(data.endpoint)extra+=' Endpoint: '+data.endpoint+'.';
  return [known[0],known[1]+extra];
}
function renderAuditEntry(a){
  let data={};
  try { data=typeof a.details==='string'?JSON.parse(a.details):(a.details||{}); } catch { data={message:String(a.details||'')}; }
  if(!data||typeof data!=='object')data={message:String(data)};
  const [heading,description]=auditDescription(String(a.action||''),data);
  const warning=data.status==='not_configured'||data.status==='failed';
  const date=new Date(a.timestamp);
  const when=Number.isNaN(date.getTime())?String(a.timestamp||''):date.toLocaleString();
  return `<div class="activity" style="align-items:flex-start;gap:14px">
    <div style="min-width:0;flex:1">
      <strong style="font-size:14px">${esc(heading)}</strong>
      <p style="margin:7px 0;color:#a5b4c8;line-height:1.6;font-size:13px">${esc(description)}</p>
      ${warning?'<span style="color:#f5c178;font-size:12px">Attention required</span>':''}
      <details style="margin-top:10px"><summary style="cursor:pointer;color:#8ebaff;font-size:12px">View technical details</summary>
      <div style="font-size:12px;color:#94a3b8;margin:9px 0">Event: ${esc(a.action)} · ${esc(when)}</div>
      <pre style="white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;font-size:12px;line-height:1.5;color:#b9c9dc;background:#0d131c;border:1px solid #273344;border-radius:8px;padding:12px">${esc(JSON.stringify(data,null,2))}</pre>
      </details>
    </div><span style="white-space:nowrap;font-size:12px;color:#8496ad">${esc(when)}</span>
  </div>`;
}
function tab(name){state.tab=name;document.querySelectorAll('.panel').forEach(e=>e.classList.toggle('active',e.id===name));document.querySelectorAll('.nav').forEach(e=>e.classList.toggle('active',e.dataset.tab===name));const titles={overview:'Certificate security',inventory:'Certificate inventory',findings:'Risk findings',incidents:'Incident response',audit:'Audit trail'};$('page-title').textContent=titles[name];$('breadcrumb').textContent=titles[name];$('page-subtitle').textContent={
  overview:'Review certificate risks and test how AEGIS PKI responds.',
  inventory:'Search the sandbox certificate inventory.',
  findings:'Review flagged certificates and the available response guidance.',
  incidents:'Review approvals, certificate changes, and verification.',
  audit:'Inspect recorded scans, incidents, and operator decisions.'
}[name];document.querySelectorAll('.nav').forEach(e=>e.setAttribute('aria-current',e.dataset.tab===name?'page':'false'));window.scrollTo({top:0})}
async function runScan(){const btn=$('scan');btn.disabled=true;btn.textContent='Scanning certificates…';try{await api('scan',{method:'POST'});await refresh();notice('Scan complete. Findings updated from local certificate files.')}catch(e){notice(e.message,true)}finally{btn.disabled=false;btn.textContent='Run security scan'}}
async function simulate(){const c=state.certs.find(c=>c.source!=='uploaded-public-cert'&&!c.compromised&&!state.incidents.some(i=>i.certificate_id===c.id&&i.status==='pending_approval'));if(!c)return notice('No eligible certificates available',true);if(!confirm(`Simulate a compromised private key for ${c.hostname}? This creates a test incident only.`))return;try{const result=await api('simulate-compromise',{method:'POST',body:JSON.stringify({certificate_id:c.id})});state.animatedIncident=result.incident_id;await refresh();tab('incidents');notice('Simulated compromise created. Human approval is required for remediation.')}catch(e){notice(e.message,true)}}
function openCertificateReview(id){
  const cert=state.certs.find(c=>c.id===id);
  if(!cert)return;
  const findings=state.findings.filter(f=>f.certificate_id===id);
  const previous=state.incidents.filter(i=>i.certificate_id===id);
  const eligible=cert.source!=='uploaded-public-cert'&&findings.length>0&&!previous.some(i=>['pending_approval','approved','executing'].includes(i.status));
  const realAcmeEligible=cert.hostname==='service-01.demo.local'&&cert.source!=='uploaded-public-cert'&&cert.active===true&&!cert.revoked&&!previous.some(i=>['pending_approval','approved','executing'].includes(i.status));
  let modal=document.getElementById('certificate-review-dialog');
  if(!modal){modal=document.createElement('dialog');modal.id='certificate-review-dialog';modal.style.cssText='max-width:570px;width:calc(100% - 30px);background:#101c2c;color:#f0f4fa;border:1px solid #53647c;border-radius:14px;padding:24px;max-height:85vh;overflow:auto';document.body.appendChild(modal);}
  const completed=state.incidents.filter(i=>i.status==='resolved'&&i.type==='CERTIFICATE_RENEWAL').find(i=>state.steps[i.id]?.comparison?.after?.serial===cert.serial);
  const before=completed&&state.steps[completed.id]?.comparison?.before;
  const expiryFinding=findings.some(f=>['EXPIRED','EXPIRING_7D','EXPIRING_14D','EXPIRING_30D'].includes(f.code));
  modal.innerHTML=`<h2 style="margin:0 0 12px">Certificate review</h2><p><strong>${esc(cert.hostname)}</strong></p><p>Expires: ${esc(new Date(cert.expires_at).toLocaleDateString())} · Key: ${esc(cert.key_type)}-${esc(cert.key_bits)}</p>
    <h3>Detected issues</h3>${findings.length?findings.map(f=>`<p style="border-left:3px solid #e7a65a;padding-left:10px"><strong>${esc(f.code)}</strong> (${esc(f.severity)}): ${esc(f.message)}</p>`).join(''):'<p>No current policy findings. Certificate is healthy.</p>'}
    ${completed?`<div style="border-left:3px solid #64c99a;padding-left:12px"><strong>Renewed successfully in sandbox</strong><p>Old expiry: ${esc(before?.expires_at||'See audit')}<br>New expiry: ${esc(cert.expires_at)}<br>Old serial: ${esc(before?.serial||'See audit')}<br>New serial: ${esc(cert.serial)}</p><p>Fix: Replaced the expiring certificate with a fresh RSA-2048 certificate, updated the active sandbox inventory, and recorded revocation and verification evidence.</p></div>`:''}
    ${cert.source==='uploaded-public-cert'?'<p>Imported public certificate: analysis only. Its owner/CA must authorize renewal.</p>':''}
    ${previous.length?'<h3>Remediation history</h3>'+previous.map(i=>`<p>${esc(i.type)}: <strong>${esc(i.status)}</strong> ${esc(i.created_at)}</p>`).join(''):''}
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:18px">${eligible?`<button class="primary" id="request-cert-renewal">${expiryFinding?'Renew certificate':'Fix certificate'} (sandbox)</button>`:''}${realAcmeEligible?'<button class="secondary" id="request-real-acme">Request real ACME renewal (Ubuntu worker)</button>':''}<button class="secondary" id="close-cert-review">Close</button></div>`;
  modal.querySelector('#close-cert-review').onclick=()=>modal.close();
  modal.querySelector('#request-real-acme')?.addEventListener('click',async()=>{
    const approver='APEX Demo Operator';
    if(!confirm('Queue REAL ACME renewal for service-01.demo.local? This will execute only if the separately authenticated Ubuntu worker is online and explicitly enabled.'))return;
    const btn=modal.querySelector('#request-real-acme');btn.disabled=true;
    try{
      const request=await api('certificates/real-acme-request',{method:'POST',body:JSON.stringify({certificate_id:id})});
      const job=await api('incidents/'+request.incident_id+'/approve-local-acme',{method:'POST',body:JSON.stringify({approver:approver.trim(),hostname:cert.hostname})});
      modal.close();await refresh();tab('incidents');
      notice('Real ACME job '+job.job_id+' queued. Ubuntu worker must be online with --enable-acme; deployment and revocation are NOT yet verified.');
    }catch(err){btn.disabled=false;await refresh();notice('Real ACME request: '+err.message,true)}
  });
  modal.querySelector('#request-cert-renewal')?.addEventListener('click',async()=>{
    const approver='APEX Demo Operator';
    if(!confirm('Approve sandbox certificate renewal for '+cert.hostname+'? The old certificate will be superseded and the replacement will be validated.'))return;
    const btn=modal.querySelector('#request-cert-renewal');btn.disabled=true;btn.textContent='Renewing…';
    let incidentId=null;
    try{
      const request=await api('certificates/renewal-request',{method:'POST',body:JSON.stringify({certificate_id:id})});
      incidentId=request.incident_id;
      const result=await api('incidents/'+incidentId+'/approve',{method:'POST',body:JSON.stringify({approver:approver.trim()})});
      modal.close();await refresh();
      const newCert=state.certs.find(c=>c.id===result.new_certificate_id);
      if(newCert)openCertificateReview(newCert.id);
      notice('Certificate renewed in sandbox. Replacement active; details and audit recorded.');
    }catch(err){
      await refresh();modal.close();
      if(incidentId)tab('incidents');
      notice('Renewal failed or requires attention: '+err.message,true);
    }
  });
  modal.showModal();
}
document.addEventListener('click',async e=>{const certRow=e.target.closest('[data-open-cert]');if(certRow){openCertificateReview(certRow.dataset.openCert);return;}const nav=e.target.closest('[data-tab],[data-goto]');if(nav)tab(nav.dataset.tab||nav.dataset.goto);const finding=e.target.closest('[data-certificate]');if(finding){state.selectedCert=finding.dataset.certificate;tab('overview');renderMap();$('map-service').focus({preventScroll:true});$('certificate-map').scrollIntoView({block:'center'});}const approve=e.target.closest('[data-approve]');if(approve){const actor='APEX Demo Operator';try{await api(`incidents/${approve.dataset.approve}/approve`,{method:'POST',body:JSON.stringify({approver:actor})});state.animatedIncident=approve.dataset.approve;await refresh();notice('Sandbox rotation complete. See incident evidence for the live TLS check.')}catch(err){notice(err.message,true)}}const reject=e.target.closest('[data-reject]');if(reject){try{await api(`incidents/${reject.dataset.reject}/reject`,{method:'POST'});await refresh();notice('Remediation rejected; compromised certificate remains at risk.')}catch(err){notice(err.message,true)}}});
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

document.getElementById('llm-check')?.addEventListener('click',async()=>{const btn=$('llm-check');btn.disabled=true;btn.textContent='Checking…';try{const data=await api('explanations');state.explanationMode=data.mode;state.explanationReason=data.reason;state.explanationNote=data.note;state.explanationHint=data.provider_hint;state.explanations=data.recommendations||[];render();notice(data.mode==='groq-llm'?'AI LLM responded successfully':data.mode==='no-findings'?'No findings to analyze':('AI fallback: '+(data.reason||'unknown error').replaceAll('_',' ')))}catch(e){notice('LLM check failed: '+e.message,true)}finally{btn.disabled=false;btn.textContent='Check LLM now'}});
document.getElementById('record-local-recovery')?.addEventListener('click',async()=>{
  const operator=prompt('Enter the operator name for this local Smallstep run');
  if(!operator?.trim())return;
  const old_serial=prompt('Enter the old CA serial in hexadecimal');
  const new_serial=prompt('Enter the new CA serial in hexadecimal');
  const sha256_fingerprint=prompt('Enter the served certificate SHA-256 fingerprint (64 hex characters)');
  if(!old_serial||!new_serial||!sha256_fingerprint)return;
  const deployment_verified=confirm('Did the trusted local TLS handshake verify the replacement?');
  const ca_revocation_confirmed=confirm('Did the local CA confirm revocation of the old certificate?');
  if(!confirm('Record these results as operator-attested evidence?'))return;
  try{
    const payload={hostname:'service-01.demo.local',old_serial:old_serial.trim(),
      new_serial:new_serial.trim(),sha256_fingerprint:sha256_fingerprint.trim(),
      deployment_verified,ca_revocation_confirmed,operator:operator.trim()};
    await api('local-recovery/evidence',{method:'POST',body:JSON.stringify(payload)});
    await refresh();
    notice('Operator-attested local recovery evidence recorded in audit.');
  }catch(e){notice('Could not record recovery evidence: '+e.message,true)}
});
document.getElementById('certificate-import-form')?.addEventListener('submit',async event=>{
  event.preventDefault();
  const file=document.getElementById('import-file').files[0];
  const hostname=document.getElementById('import-hostname').value.trim().toLowerCase();
  if(!file)return;
  if(file.size>65536)return notice('Public certificate file must be under 64 KB.',true);
  try{
    const pem=await file.text();
    const result=await api('certificates/import',{method:'POST',body:JSON.stringify({hostname,pem})});
    await refresh();
    notice('Imported and scanned public certificate for '+result.hostname);
    event.target.reset();
  }catch(error){notice('Import failed: '+error.message,true)}
});

// Refresh pending worker approvals without requiring the operator to reload the page.
setInterval(()=>{if(state.tab==='incidents'&&state.incidents.some(i=>i.type==='REAL_ACME_RENEWAL'&&['approved','executing'].includes(i.status)))refresh();},5000);

document.getElementById('certificate-bulk-form')?.addEventListener('submit',async event=>{
  event.preventDefault();
  const file=document.getElementById('bulk-import-file').files[0];
  const output=document.getElementById('bulk-import-results');
  if(!file)return;
  if(file.size>131072){output.textContent='File too large (128 KB maximum).';return;}
  const button=event.target.querySelector('button[type=submit]');
  button.disabled=true;output.textContent='Analyzing file…';
  try{
    const pem=await file.text();
    const isPem=pem.includes('-----BEGIN CERTIFICATE-----');
    const result=await api(isPem?'certificates/import-bulk':'certificates/import-metadata',{method:'POST',body:JSON.stringify(isPem?{pem}:{text:pem})});
    if(isPem){output.textContent=result.imported+' of '+result.count+' certificates imported and scanned. '+result.results.filter(r=>!r.ok).map(r=>'#'+r.index+': '+r.error).join('; ');}
    else {const accepted=result.results.filter(item=>item.ok);for(const item of accepted){unverifiedImports=unverifiedImports.filter(old=>old.hostname!==item.hostname);unverifiedImports.push(item);}unverifiedImports=unverifiedImports.slice(-100);try{sessionStorage.setItem('apex_unverified_imports',JSON.stringify(unverifiedImports));}catch{}renderUnverifiedImports();output.replaceChildren();const heading=document.createElement('strong');heading.textContent='SIMULATED / UNVERIFIED — '+result.analyzed+' of '+result.count+' records analyzed. No cryptographic verification performed.';output.append(heading);const list=document.createElement('ul');for(const item of result.results){const li=document.createElement('li');li.textContent=item.ok?item.hostname+' — '+(item.risks.length?item.risks.join(', '):'No declared risks detected'):'Record '+item.index+': '+item.error;list.append(li);}output.append(list);}
    await refresh();
  }catch(error){output.textContent='Bulk import failed: '+error.message;}
  finally{button.disabled=false;}
});
