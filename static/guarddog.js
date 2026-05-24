if(typeof initLogToolbar==='function'){initLogToolbar('gd-deploy-log');initLogToolbar('gd-activity-log');}
var gdLogIndex=0,gdLogInterval=null;
function startGuarddogDeploy(){var btn=document.getElementById('gd-deploy-btn');var emailEl=document.getElementById('gd-notify-email');var errEl=document.getElementById('gd-deploy-email-err');var email=(emailEl&&emailEl.value)?emailEl.value.trim():'';if(errEl)errEl.style.display='none';if(btn)btn.disabled=true;document.getElementById('gd-log-card').style.display='block';document.getElementById('gd-deploy-log').textContent='Starting...';gdLogIndex=0;
var nickEl=document.getElementById('gd-server-nickname');var nick=(nickEl&&nickEl.value)?nickEl.value.trim():'';fetch('/api/guarddog/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_email:email,server_nickname:nick}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
if(d.error){var lg=document.getElementById('gd-log-card');var dyn=document.getElementById('gd-deploy-log');if(dyn)dyn.textContent='Error: '+d.error;if(lg&&!document.getElementById('deploy-fail-banner')){var b=document.createElement('div');b.id='deploy-fail-banner';b.style.cssText='background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:12px 16px;margin-bottom:12px;font-size:13px;color:var(--red)';b.innerHTML='<strong>\u2717 Deployment failed.</strong> Uninstall (if partial) and retry, or click Retry below.';lg.insertBefore(b,lg.querySelector('.log-box')||lg.firstChild);}if(btn){btn.disabled=false;btn.textContent='\u2717 Deployment failed \u2014 Retry';btn.style.background='var(--red)';btn.style.opacity='1';btn.onclick=function(){btn.textContent='\ud83d\udc15 Deploy Guard Dog';btn.style.background='';startGuarddogDeploy();};}return;}gdPollLog();});}
function gdSectionToggle(header){var body=header.nextElementSibling;var icon=header.querySelector('.gd-collapse-toggle');if(!body)return;if(body.style.display==='block'){body.style.display='none';if(icon)icon.style.transform='rotate(0deg)';}else{body.style.display='block';if(icon)icon.style.transform='rotate(180deg)';}}
function gdSetEnabled(enable,btnEl){var path=enable?'/api/guarddog/enable':'/api/guarddog/disable';var origHtml='';if(btnEl){btnEl.disabled=true;origHtml=btnEl.innerHTML;btnEl.innerHTML='<span class="gd-toggle-spinner"></span> '+(enable?'Enabling…':'Disabling…');}fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(d.error){if(btnEl){btnEl.disabled=false;btnEl.innerHTML=origHtml;}alert(d.error);return;}location.reload();}).catch(function(e){if(btnEl){btnEl.disabled=false;btnEl.innerHTML=origHtml;}alert(e.message||'Request failed');});}
function gdApplyDockerLogLimits(){var btn=document.getElementById('gd-docker-limits-btn');var msg=document.getElementById('gd-docker-limits-msg');if(msg){msg.textContent='Applying...';msg.style.color='var(--text-dim)';}if(btn)btn.disabled=true;fetch('/api/guarddog/apply-docker-log-limits',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(btn)btn.disabled=false;if(msg){msg.textContent=d.success?(d.message||'Done.'):(d.error||'Failed');msg.style.color=d.success?'var(--green)':'var(--red)';}}).catch(function(e){if(btn)btn.disabled=false;if(msg){msg.textContent=e.message||'Request failed';msg.style.color='var(--red)';}});}
function gdPollLog(){var logEl=document.getElementById('gd-deploy-log');function poll(){fetch('/api/guarddog/deploy/log?index='+gdLogIndex,{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
if(d.entries&&d.entries.length){if(gdLogIndex===0&&logEl)logEl.textContent='';if(logEl){logEl.textContent+=d.entries.join(String.fromCharCode(10))+String.fromCharCode(10);logEl.scrollTop=logEl.scrollHeight;}gdLogIndex+=d.entries.length;}
if(!d.running){clearInterval(gdLogInterval);var btn=document.getElementById('gd-deploy-btn');if(btn)btn.disabled=false;if(d.complete){if(logEl)logEl.textContent+=String.fromCharCode(10,10)+'Deploy complete. Refreshing...';setTimeout(function(){location.reload();},2000);}else if(d.error){var lc=document.getElementById('gd-log-card');if(logEl)logEl.textContent+=String.fromCharCode(10,10)+'\u2717 Deployment failed (see log above).';if(lc&&!document.getElementById('deploy-fail-banner')){var b=document.createElement('div');b.id='deploy-fail-banner';b.style.cssText='background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:12px 16px;margin-bottom:12px;font-size:13px;color:var(--red)';b.innerHTML='<strong>\u2717 Deployment failed.</strong> Uninstall (if partial) and retry, or click Retry below.';lc.insertBefore(b,lc.querySelector('.log-box')||lc.firstChild);}if(btn){btn.textContent='\u2717 Deployment failed \u2014 Retry';btn.style.background='var(--red)';btn.style.opacity='1';btn.onclick=function(){btn.textContent='\ud83d\udc15 Deploy Guard Dog';btn.style.background='';startGuarddogDeploy();};}}}});}poll();gdLogInterval=setInterval(poll,800);}
(function(){var gdDeploying=document.body.getAttribute('data-gd-deploying')==='true';if(gdDeploying){var c=document.getElementById('gd-log-card');if(c)c.style.display='block';gdPollLog();}})();
var gdUpdateMsgTimer=null;
function gdUpdate(){var btn=document.getElementById('gd-update-btn');var msg=document.getElementById('gd-update-msg');if(!btn)return;btn.disabled=true;clearTimeout(gdUpdateMsgTimer);if(msg){msg.textContent='Updating...';msg.style.color='var(--text-dim)';}fetch('/api/guarddog/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){btn.disabled=false;if(!msg)return;if(d.success){msg.textContent='✓ '+(d.message||'Updated — refreshing…');msg.style.color='var(--green)';gdRefreshHealth();gdRefreshMonitorHealth();setTimeout(function(){location.reload();},1500);}else{msg.textContent=d.error||'Update failed';msg.style.color='var(--red)';}}).catch(function(e){btn.disabled=false;if(msg){msg.textContent=e.message||'Request failed';msg.style.color='var(--red)';}});}
function gdUninstall(){var pw=document.getElementById('gd-uninstall-password');var msg=document.getElementById('gd-uninstall-msg');if(!pw||!msg)return;msg.textContent='';fetch('/api/guarddog/uninstall',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw.value}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(d.error){msg.textContent=d.error;return;}msg.textContent='Done. Reloading...';document.getElementById('gd-uninstall-modal').classList.remove('open');setTimeout(function(){location.reload();},800);}).catch(function(e){msg.textContent=e.message||'Request failed';});}
function gdToggleNotifications(){var body=document.getElementById('gd-notify-body');var btn=document.getElementById('gd-notify-toggle-btn');var label=document.getElementById('gd-notify-toggle-label');if(!body)return;var show=body.style.display==='none';body.style.display=show?'block':'none';if(btn){var icon=btn.querySelector('.material-symbols-outlined');if(icon)icon.textContent=show?'expand_less':'expand_more';}if(label)label.textContent=show?'Collapse':'Expand to edit';}
function gdSaveNotifications(){var el=document.getElementById('gd-save-notify-msg');var btn=document.getElementById('gd-save-notify-btn');var emailEl=document.getElementById('gd-notify-email');var nickEl=document.getElementById('gd-server-nickname');var email=(emailEl&&emailEl.value)?emailEl.value.trim():'';var nick=(nickEl&&nickEl.value)?nickEl.value.trim():'';if(el){el.textContent='Saving...';el.style.color='var(--text-dim)';}if(btn)btn.disabled=true;fetch('/api/guarddog/notifications/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_email:email,server_nickname:nick}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(btn)btn.disabled=false;if(el){el.textContent=d.success?(d.message||'Saved.'):(d.error||'Failed');el.style.color=d.success?'var(--green)':'var(--red)';}}).catch(function(e){if(btn)btn.disabled=false;if(el){el.textContent=e.message||'Request failed';el.style.color='var(--red)';}});}
function gdTestEmail(){var el=document.getElementById('gd-test-email-msg');var btn=document.getElementById('gd-test-email-btn');var email=document.getElementById('gd-notify-email');var to=(email&&email.value)?email.value.trim():'';if(!to){el.textContent='Enter an email address.';el.style.color='var(--red)';return;}el.textContent='Sending...';el.style.color='var(--text-dim)';if(btn)btn.disabled=true;fetch('/api/guarddog/test-email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to:to,save:true}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(btn)btn.disabled=false;if(d.success){el.textContent=d.message||'Sent.';el.style.color='var(--green)';}else{el.textContent=d.error||'Failed';el.style.color='var(--red)';}}).catch(function(e){if(btn)btn.disabled=false;el.textContent=e.message||'Request failed';el.style.color='var(--red)';});}
function gdSmsProviderChange(){var p=document.getElementById('gd-sms-provider');var v=p?p.value:'';document.getElementById('gd-sms-twilio').style.display=(v==='twilio')?'block':'none';document.getElementById('gd-sms-brevo').style.display=(v==='brevo')?'block':'none';var eb=document.getElementById('gd-brevo-events-btn');if(eb)eb.style.display=(v==='brevo')?'inline-block':'none';if(v==='brevo')gdSenderCheck();}
function gdSenderCheck(){var inp=document.getElementById('gd-sms-br-sender');var ok=document.getElementById('gd-sms-sender-check');var warn=document.getElementById('gd-sms-sender-warn');if(!inp||!ok||!warn)return;var n=(inp.value||'').trim().length;if(n===0){ok.style.display='none';warn.style.display='none';return;}if(n<=11){ok.style.display='inline';warn.style.display='none';}else{warn.style.display='inline';warn.textContent=n+' chars (max 11)';ok.style.display='none';}}
function gdSmsSave(){var el=document.getElementById('gd-sms-msg');var p=document.getElementById('gd-sms-provider');var provider=(p&&p.value)?p.value.trim():'';var body={provider:provider};if(provider==='twilio'){body.account_sid=document.getElementById('gd-sms-tw-account').value.trim();body.auth_token=document.getElementById('gd-sms-tw-auth').value;body.from_number=document.getElementById('gd-sms-tw-from').value.trim();body.to_numbers=document.getElementById('gd-sms-tw-to').value.trim();}else if(provider==='brevo'){body.api_key=document.getElementById('gd-sms-br-api').value;body.sender=document.getElementById('gd-sms-br-sender').value.trim();body.to_numbers=document.getElementById('gd-sms-br-to').value.trim();}el.textContent='Saving...';el.style.color='var(--text-dim)';fetch('/api/guarddog/sms/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(d.success){el.textContent=d.message||'Saved.';el.style.color='var(--green)';}else{el.textContent=d.error||'Failed';el.style.color='var(--red)';}}).catch(function(e){el.textContent=e.message||'Request failed';el.style.color='var(--red)';});}
function gdTestSms(){var el=document.getElementById('gd-sms-msg');var btn=document.getElementById('gd-test-sms-btn');if(!el)return;el.textContent='Sending test SMS...';el.style.color='var(--text-dim)';if(btn)btn.disabled=true;fetch('/api/guarddog/test-sms',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(btn)btn.disabled=false;if(d.success){el.textContent=d.message||'Test SMS sent.';el.style.color='var(--green)';}else{el.textContent=d.error||'Failed';el.style.color='var(--red)';}}).catch(function(e){if(btn)btn.disabled=false;el.textContent=e.message||'Request failed';el.style.color='var(--red)';});}
function gdBrevoSmsEvents(){var box=document.getElementById('gd-sms-events');var btn=document.getElementById('gd-brevo-events-btn');if(!box)return;box.style.display='block';box.textContent='Loading...';if(btn)btn.disabled=true;fetch('/api/guarddog/brevo-sms-events?days=1',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(btn)btn.disabled=false;if(d.error){box.innerHTML='<span style="color:var(--red)">'+d.error+'</span>';return;}var ev=d.events||[];if(ev.length===0){box.textContent='No SMS events in the last 24h (tag: GuardDog). Send a test SMS and try again.';return;}var lines=ev.map(function(e){var d=e.date?new Date(e.date):null;var t=d?d.toLocaleString():e.date||'-';var evt=e.event||'-';var ph=e.phoneNumber||'';var r=e.reason?(' - '+e.reason):'';return t+' | '+evt+(ph?' | '+ph:'')+r;});box.textContent=lines.join('\n');}).catch(function(e){if(btn)btn.disabled=false;box.innerHTML='<span style="color:var(--red)">Request failed</span>';});}
function gdLoadActivityLog(){var el=document.getElementById('gd-activity-log');if(!el)return;el.textContent='Loading...';var fromVal=document.getElementById('gd-log-from')?document.getElementById('gd-log-from').value:'';var toVal=document.getElementById('gd-log-to')?document.getElementById('gd-log-to').value:'';var q='';if(fromVal)q+='from='+encodeURIComponent(fromVal)+'&';if(toVal)q+='to='+encodeURIComponent(toVal)+'&';fetch('/api/guarddog/activity-log?'+q,{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(d.error){el.textContent='Error: '+d.error;return;}if(!d.entries||d.entries.length===0){el.textContent='No entries'+(fromVal||toVal?' for this date range':'')+'.';return;}el.textContent=d.entries.map(function(e){return e.raw;}).join(String.fromCharCode(10));}).catch(function(e){el.textContent='Request failed: '+(e.message||'Unknown error');});}
async function gdRefreshCotSize(){var el=document.getElementById('gd-cot-db-size');if(!el)return;el.textContent='...';el.style.color='';var mc=document.getElementById('gd-cot-msg-count');var dt=document.getElementById('gd-cot-dead-tuples');try{var r=await fetch('/api/takserver/cot-db-size');var d=await r.json();el.textContent=d.error?d.error:(d.size_human||'-');var b=d.size_bytes;if(typeof b==='number'&&!d.error){var gb25=25*1024*1024*1024;var gb40=40*1024*1024*1024;if(b<gb25)el.style.color='var(--green)';else if(b<gb40)el.style.color='var(--yellow)';else el.style.color='var(--red)';}if(mc){mc.textContent=typeof d.message_count==='number'?d.message_count.toLocaleString():'—';}if(dt){var dtv=d.dead_tuples;dt.textContent=typeof dtv==='number'?dtv.toLocaleString():'—';if(typeof dtv==='number'){dt.style.color=dtv>1000000?'var(--red)':dtv>100000?'var(--yellow)':'var(--green)';}}}catch(e){el.textContent='Error';}}
function _gdVacuumSetUI(running,full,secs){var msg=document.getElementById('gd-vacuum-msg');var btnA=document.getElementById('gd-vacuum-analyze-btn');var btnF=document.getElementById('gd-vacuum-full-btn');var btnR=document.getElementById('gd-reindex-btn');[btnA,btnF,btnR].forEach(function(b){if(b){b.disabled=running;b.style.opacity=running?'0.4':'1';b.style.pointerEvents=running?'none':'auto';}});if(running&&msg){var elapsed='';if(secs>0){var m=Math.floor(secs/60);elapsed=m>0?' ('+m+'m '+secs%60+'s)':' ('+secs+'s)';}msg.textContent=(full?'Running VACUUM FULL':'Running VACUUM ANALYZE')+'...'+elapsed;msg.style.color='var(--text-dim)';}}
async function _gdPollVacuumStatus(){var msg=document.getElementById('gd-vacuum-msg');var out=document.getElementById('gd-vacuum-output');try{var r=await fetch('/api/takserver/vacuum/status');var d=await r.json();if(d.running){_gdVacuumSetUI(true,d.full,d.elapsed_secs||0);setTimeout(_gdPollVacuumStatus,5000);}else{if(d.error){if(msg){msg.textContent=d.error;msg.style.color='var(--red)';}}else if(d.result!==null){if(msg){msg.textContent='Done.';msg.style.color='var(--green)';}if(out&&d.result){out.textContent=d.result;out.style.display='block';}gdRefreshCotSize();}_gdVacuumSetUI(false,false,0);}}catch(e){setTimeout(_gdPollVacuumStatus,10000);}}
async function gdRunVacuum(full){var msg=document.getElementById('gd-vacuum-msg');var out=document.getElementById('gd-vacuum-output');if(full&&!confirm('VACUUM FULL locks the CoT tables. Run when TAK Server is not running. Continue?'))return;if(out){out.style.display='none';out.textContent='';}_gdVacuumSetUI(true,full,0);try{var r=await fetch('/api/takserver/vacuum',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({full:full})});var d=await r.json();if(d.success||d.status==='running'){_gdPollVacuumStatus();}else{if(msg){msg.textContent=d.error||'Failed';msg.style.color='var(--red)';}_gdVacuumSetUI(false,false,0);}}catch(e){if(msg){msg.textContent='Request failed';msg.style.color='var(--red)';}_gdVacuumSetUI(false,false,0);}}
async function gdRunReindex(){var msg=document.getElementById('gd-vacuum-msg');var out=document.getElementById('gd-vacuum-output');var btn=document.getElementById('gd-reindex-btn');if(!confirm('Rebuild all indexes on the CoT database? Safe while running but may take a while.'))return;if(msg){msg.textContent='Running REINDEX...';msg.style.color='var(--text-dim)';}if(out){out.style.display='none';out.textContent='';}if(btn){btn.disabled=true;}try{var r=await fetch('/api/takserver/reindex',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});var d=await r.json();if(d.success){if(msg){msg.textContent='Done.';msg.style.color='var(--green)';}if(out&&d.output){out.textContent=d.output;out.style.display='block';}}else{if(msg){msg.textContent=d.error||'Failed';msg.style.color='var(--red)';}}if(btn){btn.disabled=false;}}catch(e){if(msg){msg.textContent='Request failed';msg.style.color='var(--red)';}if(btn){btn.disabled=false;}}}
function gdToggleService(id){var row=document.getElementById('gd-svc-'+id);if(row)row.classList.toggle('open');}
function gdDeployHealthAgent(){var btns=document.querySelectorAll('#gd-deploy-agent-btn, .gd-deploy-agent-btn');var msgEls=document.querySelectorAll('#gd-deploy-agent-msg, .gd-deploy-agent-msg-inline');btns.forEach(function(b){b.disabled=true;});msgEls.forEach(function(m){m.textContent=' Deploying...';m.style.color='var(--text-dim)';});fetch('/api/guarddog/deploy-health-agent',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){btns.forEach(function(b){b.disabled=false;});msgEls.forEach(function(m){m.textContent=d.success?(d.message||' Done. Refreshing...'):(' '+d.error);m.style.color=d.success?'var(--green)':'var(--red)';});if(d.success)setTimeout(function(){location.reload();},1500);}).catch(function(e){btns.forEach(function(b){b.disabled=false;});msgEls.forEach(function(m){m.textContent=' Request failed';m.style.color='var(--red)';});});}
function gdFirewallRefresh(){var box=document.getElementById('gd-fw-rules');var msg=document.getElementById('gd-fw-msg');if(box)box.textContent='Loading firewall status...';fetch('/api/firewall/status',{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(!box)return;if(!d.supported){box.textContent=d.error||'Firewall status unavailable';if(msg){msg.textContent=d.error||'Unavailable';msg.style.color='var(--yellow)';}return;}var lines=[];lines.push('Status: '+(d.enabled?'active':'inactive'));if(d.rules&&d.rules.length){lines.push('');lines.push(d.rules.join(String.fromCharCode(10)));}else{lines.push('');lines.push('No explicit allow rules found.');}box.textContent=lines.join(String.fromCharCode(10));if(msg){msg.textContent='';}}).catch(function(e){if(box)box.textContent='Failed to load firewall status';if(msg){msg.textContent=e.message||'Request failed';msg.style.color='var(--red)';}});}
function gdFirewallOpenPort(){var p=document.getElementById('gd-fw-port');var proto=document.getElementById('gd-fw-proto');var btn=document.getElementById('gd-fw-open-btn');var msg=document.getElementById('gd-fw-msg');var port=parseInt((p&&p.value)||'',10);var protocol=(proto&&proto.value)||'tcp';if(!port||port<1||port>65535){if(msg){msg.textContent='Enter a valid port (1-65535).';msg.style.color='var(--red)';}return;}if(btn)btn.disabled=true;if(msg){msg.textContent='Opening '+port+'/'+protocol+'...';msg.style.color='var(--text-dim)';}fetch('/api/firewall/open-port',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port:port,protocol:protocol}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(btn)btn.disabled=false;if(!d.success){if(msg){msg.textContent=d.error||'Failed';msg.style.color='var(--red)';}return;}if(msg){msg.textContent=d.message||'Opened';msg.style.color='var(--green)';}gdFirewallRefresh();}).catch(function(e){if(btn)btn.disabled=false;if(msg){msg.textContent=e.message||'Request failed';msg.style.color='var(--red)';}});}
function gdFirewallClosePort(){var p=document.getElementById('gd-fw-port');var proto=document.getElementById('gd-fw-proto');var btn=document.getElementById('gd-fw-close-btn');var msg=document.getElementById('gd-fw-msg');var port=parseInt((p&&p.value)||'',10);var protocol=(proto&&proto.value)||'tcp';if(!port||port<1||port>65535){if(msg){msg.textContent='Enter a valid port (1-65535).';msg.style.color='var(--red)';}return;}if(!confirm('Close '+port+'/'+protocol+' inbound rule?'))return;if(btn)btn.disabled=true;if(msg){msg.textContent='Closing '+port+'/'+protocol+'...';msg.style.color='var(--text-dim)';}fetch('/api/firewall/close-port',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port:port,protocol:protocol}),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){if(btn)btn.disabled=false;if(!d.success){if(msg){msg.textContent=d.error||'Failed';msg.style.color='var(--red)';}return;}if(msg){msg.textContent=d.message||'Closed';msg.style.color='var(--green)';}gdFirewallRefresh();}).catch(function(e){if(btn)btn.disabled=false;if(msg){msg.textContent=e.message||'Request failed';msg.style.color='var(--red)';}});}
function gdRefreshHealth(){fetch('/api/guarddog/health?_='+Date.now(),{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.json();}).then(function(h){for(var id in h){var el=document.getElementById('gd-health-'+id);if(!el)continue;var s=h[id];el.className='guard-service-health '+(s||'fail');el.title=s==='ok'?'Healthy':s==='caution'?'Some checks failing': 'Unhealthy';}}).catch(function(){});}
function gdRefreshMonitorHealth(){var items=document.querySelectorAll('[data-monitor-id]');if(!items.length)return;var ids=[];items.forEach(function(el){var mid=el.getAttribute('data-monitor-id');if(mid)ids.push(mid);});if(!ids.length)return;fetch('/api/guarddog/monitor-health?ids='+ids.join(','),{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(h){for(var mid in h){var el=document.getElementById('gd-mh-'+mid);if(!el)continue;el.className='guard-monitor-health '+(h[mid]?'ok':'fail');el.title=h[mid]?'Healthy':'Unhealthy';}}).catch(function(){});}
if (document.getElementById('gd-activity-log')) gdLoadActivityLog();
if (document.getElementById('gd-cot-db-size')){gdRefreshCotSize();fetch('/api/takserver/vacuum/status').then(function(r){return r.json();}).then(function(d){if(d.running){_gdVacuumSetUI(true,d.full,d.elapsed_secs||0);_gdPollVacuumStatus();}}).catch(function(){});}
if (document.getElementById('gd-fw-rules')) gdFirewallRefresh();
if (document.querySelector('.guard-service-row')){gdRefreshHealth();gdRefreshMonitorHealth();setInterval(gdRefreshHealth,30000);setInterval(gdRefreshMonitorHealth,30000);}
if (document.getElementById('gd-sms-provider')) gdSmsProviderChange();
if (document.getElementById('gd-sms-br-sender')) gdSenderCheck();

function gdRefreshDiskIO(){
  var card=document.getElementById('gd-diskio-card');if(!card)return;
  var sel=document.getElementById('gd-dio-range-sel');
  var hours=sel?sel.value:'72';
  var empty=document.getElementById('gd-dio-empty');
  var rbtn=document.getElementById('gd-dio-refresh-btn');
  if(rbtn){rbtn.textContent='Refreshing…';rbtn.disabled=true;}
  fetch('/api/guarddog/diskio-history?hours='+hours,{credentials:'same-origin'}).then(function(r){
    if(!r.ok){return r.json().then(function(err){var msg=err.error||('HTTP '+r.status);if(empty){empty.style.display='flex';empty.textContent=msg;}console.error('diskio API',msg,err.traceback||'');return Promise.reject(msg);}).catch(function(){if(empty){empty.style.display='flex';empty.textContent='API error ('+r.status+')';}return Promise.reject('status '+r.status);});}
    var ct=r.headers.get('content-type')||'';
    if(ct.indexOf('json')<0){if(empty)empty.textContent='Auth redirect — reload page';return Promise.reject('not json');}
    return r.json();
  }).then(function(d){
    if(!d)return;
    var cur=document.getElementById('gd-dio-current');
    var h1=document.getElementById('gd-dio-1h');
    var h24=document.getElementById('gd-dio-24h');
    var rng=document.getElementById('gd-dio-range');
    if(!d.entries||d.entries.length===0){if(empty){empty.style.display='flex';empty.textContent='No data yet — first sample in ~15 min after Guard Dog deploy';}return;}
    if(empty)empty.style.display='none';
    var last=d.entries[d.entries.length-1].v;
    if(cur){cur.textContent=last+' MB/s';cur.style.color=last<50?'var(--red)':last<100?'var(--yellow)':'var(--green)';}
    if(h1){h1.textContent=d.avg_1h!==null?d.avg_1h+' MB/s':'—';if(d.avg_1h!==null)h1.style.color=d.avg_1h<50?'var(--red)':d.avg_1h<100?'var(--yellow)':'var(--green)';}
    if(h24){h24.textContent=d.avg_24h!==null?d.avg_24h+' MB/s':'—';if(d.avg_24h!==null)h24.style.color=d.avg_24h<50?'var(--red)':d.avg_24h<100?'var(--yellow)':'var(--green)';}
    if(rng)rng.textContent=(d.min!==null?d.min:'—')+' / '+(d.max!==null?d.max:'—')+' MB/s';
    gdDrawDiskIOChart(d.entries);
    if(rbtn){rbtn.textContent='Updated';rbtn.style.color='var(--green)';setTimeout(function(){rbtn.textContent='Refresh';rbtn.style.color='';rbtn.disabled=false;},1200);}
  }).catch(function(e){console.error('diskio fetch error',e);if(rbtn){rbtn.textContent='Refresh';rbtn.disabled=false;}});
}
function gdDrawDiskIOChart(entries){
  var canvas=document.getElementById('gd-dio-chart');if(!canvas||!canvas.getContext)return;
  var ctx=canvas.getContext('2d');
  var dpr=window.devicePixelRatio||1;
  canvas.width=canvas.offsetWidth*dpr;canvas.height=canvas.offsetHeight*dpr;
  ctx.scale(dpr,dpr);
  var w=canvas.offsetWidth,h=canvas.offsetHeight;
  ctx.clearRect(0,0,w,h);
  if(entries.length<2)return;
  var vals=entries.map(function(e){return e.v;});
  var maxV=Math.max.apply(null,vals);var minV=Math.min.apply(null,vals);
  var range=maxV-minV||1;
  var pad={t:8,b:18,l:4,r:4};
  var cw=w-pad.l-pad.r,ch=h-pad.t-pad.b;
  // Warning threshold line at 50 MB/s
  if(maxV>50){
    var yWarn=pad.t+ch-(50-minV)/range*ch;
    ctx.strokeStyle='rgba(239,68,68,0.3)';ctx.lineWidth=1;ctx.setLineDash([4,4]);
    ctx.beginPath();ctx.moveTo(pad.l,yWarn);ctx.lineTo(w-pad.r,yWarn);ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle='rgba(239,68,68,0.5)';ctx.font='9px JetBrains Mono,monospace';
    ctx.fillText('50 MB/s',pad.l+2,yWarn-3);
  }
  // Gradient fill
  var grad=ctx.createLinearGradient(0,pad.t,0,h-pad.b);
  grad.addColorStop(0,'rgba(6,182,212,0.25)');grad.addColorStop(1,'rgba(6,182,212,0.02)');
  ctx.beginPath();
  for(var i=0;i<vals.length;i++){
    var x=pad.l+(i/(vals.length-1))*cw;
    var y=pad.t+ch-(vals[i]-minV)/range*ch;
    if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
  }
  ctx.lineTo(pad.l+cw,h-pad.b);ctx.lineTo(pad.l,h-pad.b);ctx.closePath();
  ctx.fillStyle=grad;ctx.fill();
  // Line
  ctx.beginPath();
  for(var i=0;i<vals.length;i++){
    var x=pad.l+(i/(vals.length-1))*cw;
    var y=pad.t+ch-(vals[i]-minV)/range*ch;
    if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
  }
  ctx.strokeStyle='#06b6d4';ctx.lineWidth=1.5;ctx.stroke();
  // Dots for low values
  for(var i=0;i<vals.length;i++){
    if(vals[i]<50){
      var x=pad.l+(i/(vals.length-1))*cw;
      var y=pad.t+ch-(vals[i]-minV)/range*ch;
      ctx.beginPath();ctx.arc(x,y,3,0,Math.PI*2);ctx.fillStyle='var(--red)';ctx.fill();
    }
  }
  // Time labels
  ctx.fillStyle='rgba(148,163,184,0.6)';ctx.font='9px JetBrains Mono,monospace';
  if(entries.length>0){
    var fd=new Date(entries[0].t);var ld=new Date(entries[entries.length-1].t);
    var fmt=function(dt){var h=dt.getHours(),m=dt.getMinutes();return (h<10?'0':'')+h+':'+(m<10?'0':'')+m;};
    var fmtDate=function(dt){return (dt.getMonth()+1)+'/'+dt.getDate()+' '+fmt(dt);};
    var spanH=(ld-fd)/3600000;
    var first=spanH>24?fmtDate(fd):fmt(fd);
    var last=spanH>24?fmtDate(ld):fmt(ld);
    ctx.textAlign='left';ctx.fillText(first,pad.l,h-3);
    ctx.textAlign='right';ctx.fillText(last,w-pad.r,h-3);
  }
}
function gdDownloadDiskIOReport(){
  var msg=document.getElementById('gd-dio-dl-msg');
  if(msg){msg.textContent='Generating...';msg.style.color='var(--text-dim)';}
  var sel=document.getElementById('gd-dio-range-sel');
  var hours=sel?sel.value:'72';
  window.location.href='/api/guarddog/diskio-report?hours='+hours;
  setTimeout(function(){if(msg)msg.textContent='';},3000);
}
function gdDiskioUiRefresh(){
  var mon=document.getElementById('gd-dio-enabled');
  var em=document.getElementById('gd-dio-email');
  if(em&&mon){em.disabled=!mon.checked;}
}
function gdSaveDiskioSettings(){
  var mon=document.getElementById('gd-dio-enabled');
  var em=document.getElementById('gd-dio-email');
  var msg=document.getElementById('gd-dio-enabled-msg');
  var prevMon=mon?mon.checked:false;
  var prevEm=em?em.checked:false;
  if(mon)mon.disabled=true;
  if(em)em.disabled=true;
  if(msg){msg.textContent='Saving...';msg.style.color='var(--text-dim)';}
  var body={enabled:!!(mon&&mon.checked),email_enabled:!!(em&&em.checked)};
  fetch('/api/guarddog/diskio-monitor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'}).then(function(r){return r.json();}).then(function(d){
    if(mon)mon.disabled=false;
    if(em){em.disabled=!mon.checked;}
    if(!d.success){
      if(mon)mon.checked=prevMon;
      if(em)em.checked=prevEm;
      gdDiskioUiRefresh();
      if(msg){msg.textContent=d.error||'Failed';msg.style.color='var(--red)';}
      return;
    }
    gdDiskioUiRefresh();
    if(msg){msg.textContent='Saved.';msg.style.color='var(--green)';setTimeout(function(){if(msg)msg.textContent='';},4500);}
  }).catch(function(e){
    if(mon){mon.disabled=false;mon.checked=prevMon;}
    if(em){em.checked=prevEm;}
    gdDiskioUiRefresh();
    if(msg){msg.textContent=e.message||'Request failed';msg.style.color='var(--red)';}
  });
}
if(document.getElementById('gd-diskio-card')){gdDiskioUiRefresh();gdRefreshDiskIO();setInterval(gdRefreshDiskIO,300000);}

function doConsoleRollback(){
  var modal=document.getElementById('gd-rollback-modal');
  var pw=document.getElementById('gd-rollback-password');
  var msg=document.getElementById('gd-rollback-msg');
  if(!modal)return;
  if(pw)pw.value='';
  if(msg)msg.textContent='';
  modal.classList.add('open');
  setTimeout(function(){if(pw)pw.focus();},100);
}
function doConsoleRollbackSubmit(){
  var pw=document.getElementById('gd-rollback-password');
  var msg=document.getElementById('gd-rollback-msg');
  var btn=document.querySelector('#gd-rollback-modal .btn:not(.btn-ghost)');
  if(!pw||!msg)return;
  var password=pw.value;
  if(!password){msg.textContent='Password required.';msg.style.color='var(--red)';return;}
  msg.textContent='Rolling back…';msg.style.color='var(--text-dim)';
  if(btn){btn.disabled=true;btn.textContent='Rolling back…';}
  fetch('/api/console/rollback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:password}),credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.ok){
        msg.style.color='var(--green)';msg.textContent='✓ '+d.message;
        setTimeout(function(){window.location.reload();},10000);
      }else{
        if(btn){btn.disabled=false;btn.textContent='↩ Roll Back';}
        msg.style.color='var(--red)';msg.textContent=d.error||'Rollback failed';
      }
    })
    .catch(function(e){
      if(btn){btn.disabled=false;btn.textContent='↩ Roll Back';}
      msg.style.color='var(--red)';msg.textContent=e.message||'Network error';
    });
}
