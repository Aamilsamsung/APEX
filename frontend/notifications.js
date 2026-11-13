/* APEX in-app incident notifications. Polls sandbox incidents; no external push required. */
(()=>{
  const root=document.getElementById('apex-alert-root');
  if(!root)return;
  const bell=document.getElementById('apex-alert-bell');
  const count=document.getElementById('apex-alert-count');
  const panel=document.getElementById('apex-alert-panel');
  const toast=document.getElementById('apex-alert-toast');
  const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let previous=new Map(),initialized=false,muted=new Set(),busy=false;
  function label(i){return i.status==='pending_approval'?'Approval required':i.status==='resolved'?'Incident resolved':i.status==='rejected'?'Remediation rejected':i.status==='failed'?'Remediation failed':'Incident updated'}
  function render(items){
    const pending=items.filter(i=>i.status==='pending_approval');
    count.textContent=pending.length>9?'9+':String(pending.length);
    count.hidden=!pending.length;
    bell.setAttribute('aria-label','Notifications, '+pending.length+' pending approvals');
    panel.innerHTML=items.slice(0,12).map(i=>'<div class="apex-alert-item"><strong>'+esc(label(i))+'</strong><p>'+esc(i.type)+' · '+esc(i.id)+'</p><button type="button" data-apex-incident="'+esc(i.id)+'">View incident</button></div>').join('')||'<p class="apex-alert-empty">No incidents yet.</p>';
  }
  function show(i){
    if(muted.has(i.id+':'+i.status))return;
    toast.hidden=false;
    toast.innerHTML='<button type="button" class="apex-alert-close" aria-label="Dismiss notification">×</button><div class="apex-alert-eyebrow">AEGIS PKI · SECURITY EVENT</div><h3>'+esc(label(i))+'</h3><p>'+esc(i.type)+' · Incident '+esc(i.id)+'</p><div class="apex-alert-actions"><button type="button" data-apex-incident="'+esc(i.id)+'">Review incident</button></div>';
    toast.querySelector('.apex-alert-close').onclick=()=>{muted.add(i.id+':'+i.status);toast.hidden=true};
  }
  async function poll(){
    if(busy||document.hidden)return;
    busy=true;
    try{
      const response=await fetch('/api/incidents',{cache:'no-store'});
      if(!response.ok)throw Error('Incident refresh failed');
      const items=await response.json();
      if(!Array.isArray(items))return;
      render(items);
      const current=new Map(items.map(i=>[i.id,i.status]));
      if(initialized){
        const changed=items.find(i=>previous.has(i.id)&&previous.get(i.id)!==i.status)||items.find(i=>!previous.has(i.id));
        if(changed)show(changed);
      }else{
        const pending=items.find(i=>i.status==='pending_approval');
        if(pending)show(pending);
        initialized=true;
      }
      previous=current;
    }catch(e){/* Leave last known notification state visible during outages. */}
    finally{busy=false}
  }
  bell.onclick=()=>{panel.hidden=!panel.hidden;bell.setAttribute('aria-expanded',String(!panel.hidden))};
  root.addEventListener('click',e=>{
    const target=e.target.closest('[data-apex-incident]');
    if(!target)return;
    panel.hidden=true;toast.hidden=true;
    const incidentsNav=document.querySelector('[data-tab="incidents"]');
    incidentsNav?.click();
    const cards=[...document.querySelectorAll('.incident-card')];
    const index=(window.state?.incidents||[]).findIndex(i=>i.id===target.dataset.apexIncident);
    (cards[index]||document.getElementById('incident-list'))?.scrollIntoView({behavior:'smooth',block:'start'});
  });
  poll();
  setInterval(poll,12000);
})();
