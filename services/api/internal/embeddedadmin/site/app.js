'use strict';
const byId=id=>document.getElementById(id);
let token=''; // Volatile only: never persisted to sessionStorage/localStorage or URLs.
const show=(id,state)=>{byId(id).hidden=!state;};
const message=(text,isError=false)=>{byId('status').textContent=text;byId('status').classList.toggle('error',isError);};
async function api(path, method='GET',body=null,bootstrapToken=''){
  const headers={'Accept':'application/json'};
  if(body!==null) headers['Content-Type']='application/json';
  if(token) headers.Authorization=`Bearer ${token}`;
  if(bootstrapToken) headers['X-NeverLauncher-Bootstrap-Token']=bootstrapToken;
  const response=await fetch(path,{method,headers,body:body===null?undefined:JSON.stringify(body),cache:'no-store',redirect:'error',credentials:'same-origin'});
  let result;try{result=await response.json();}catch{throw new Error(`HTTP ${response.status}: invalid JSON`)}
  if(!response.ok)throw new Error(result?.error?.message||`HTTP ${response.status}`);
  return result?.data??result;
}
async function readiness(){
  try{
    const data=await api('/api/v1/install/readiness');
    message(`Readiness: ${data.status}; установка завершена: ${data.installationCompleted?'да':'нет'}`);
    show('bootstrap',!data.installationCompleted&&!data.bootstrapTokenConsumed);
    show('login',!token);
    show('admin',!!token);
  }catch(e){message(`Backend недоступен: ${e.message}`,true);show('bootstrap',false);show('login',false);show('admin',false)}
}
const values=id=>Object.fromEntries(new FormData(byId(id)));
byId('bootstrap-form').addEventListener('submit',async event=>{
 event.preventDefault();const form=byId('bootstrap-form');const fields=values('bootstrap-form');const submit=form.querySelector('button');submit.disabled=true;
 try{const result=await api('/api/v1/install/bootstrap-admin','POST',{email:fields.email,displayName:fields.displayName,password:fields.password},fields.bootstrapToken);form.reset();message(`Владелец ${result.email} создан. Выполните вход.`);show('bootstrap',false);show('login',true)}catch(e){message(e.message,true)}finally{submit.disabled=false}
});
byId('login-form').addEventListener('submit',async event=>{
 event.preventDefault();const fields=values('login-form');const submit=byId('login-form').querySelector('button');submit.disabled=true;
 try{const result=await api('/api/v1/admin/login','POST',{email:fields.email,password:fields.password,totp:fields.totp});if(!result.token)throw new Error('Дополнительная MFA-аутентификация требуется; используйте полную Admin SPA');token=result.token;byId('login-form').reset();show('login',false);show('admin',true);message('Вход выполнен');await dashboard()}catch(e){message(e.message,true)}finally{submit.disabled=false}
});
async function dashboard(){
 try{const [overview,projects]=await Promise.all([api('/api/v1/admin/overview'),api('/api/v1/projects')]);byId('overview').textContent=JSON.stringify(overview,null,2);byId('projects').textContent=JSON.stringify(projects,null,2)}catch(e){message(e.message,true)}
}
byId('refresh').addEventListener('click',dashboard);
byId('logout').addEventListener('click',async()=>{try{await api('/api/v1/admin/logout','POST',{})}catch{}token='';byId('overview').textContent='';byId('projects').textContent='';await readiness()});
byId('project-form').addEventListener('submit',async event=>{event.preventDefault();const submit=byId('project-form').querySelector('button');submit.disabled=true;try{const result=await api('/api/v1/install/first-project','POST',values('project-form'));message(`Черновой релиз ${result.releaseId} создан`);await dashboard()}catch(e){message(e.message,true)}finally{submit.disabled=false}});
readiness();

// 0.33.2 uses the same secured Admin API as the CLI. The operator supplies
// the target project and sees the persisted state/events, never a fake success.
const migrationId=()=>byId('migration-run-id').value.trim();
async function migrationView(){
 const id=migrationId();if(!id)return;
 const [run,events]=await Promise.all([
  api(`/api/v1/admin/migration-runs/${encodeURIComponent(id)}`),
  api(`/api/v1/admin/migration-runs/${encodeURIComponent(id)}/events`)
 ]);
 byId('migration-report').textContent=JSON.stringify({run,events},null,2);
}
byId('migration-create').addEventListener('submit',async e=>{
 e.preventDefault();const button=e.currentTarget.querySelector('button');button.disabled=true;
 try{
  const idempotencyKey=values('migration-create').idempotencyKey;
  const result=await api('/api/v1/admin/migration-runs','POST',{projectId:values('migration-create').projectId,idempotencyKey,sourceKind:'gravit'});
  byId('migration-run-id').value=result.id;await migrationView();message('Migration run создан. Выполните baseline и загрузите ZIP для анализа.');
 }catch(err){message(err.message,true)}finally{button.disabled=false}
});
byId('migration-select').addEventListener('submit',async e=>{e.preventDefault();try{await migrationView()}catch(err){message(err.message,true)}});
for(const op of ['execute','pause','resume']){
 byId('migration-'+op).addEventListener('click',async e=>{
  if(!migrationId()){message('Укажите Migration run ID',true);return}
  e.currentTarget.disabled=true;
  try{await api(`/api/v1/admin/migration-runs/${encodeURIComponent(migrationId())}/${op}`,'POST',{});await migrationView();}
  catch(err){message(err.message,true)}finally{e.currentTarget.disabled=false}
 });
}

byId('migration-assess').addEventListener('submit',async event=>{
 event.preventDefault();if(!migrationId()){message('Укажите Migration run ID',true);return}
 const form=byId('migration-assess');const file=form.querySelector('[name=source]').files[0];
 if(!file||file.size>64*1024*1024){message('Требуется ZIP до 64 MiB',true);return}
 const button=form.querySelector('button');button.disabled=true;
 try{
  const response=await fetch(`/api/v1/admin/migration-runs/${encodeURIComponent(migrationId())}/compatibility`,{
   method:'POST',headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/zip','X-Gravit-Version':form.querySelector('[name=version]').value},body:file,redirect:'error',cache:'no-store',credentials:'same-origin'
  });const payload=await response.json();if(!response.ok)throw new Error(payload?.error?.message||`HTTP ${response.status}`);
  await migrationView();byId('migration-report').textContent=JSON.stringify({compatibility:payload.data},null,2);
 }catch(e){message(e.message,true)}finally{button.disabled=false}
});

// 0.33.3: source files are uploaded on demand and never persisted by Backend.
for (const action of ['inventory','export']) {
 byId('migration-'+action).addEventListener('click',async e=>{
  const id=migrationId(),file=byId('migration-assess').querySelector('[name=source]').files[0];
  if(!id||!file||file.size>512*1024*1024){message('Выберите run и исходный ZIP до 512 MiB',true);return}
  e.currentTarget.disabled=true;
  try {
   const response=await fetch(`/api/v1/admin/migration-runs/${encodeURIComponent(id)}/${action}`,{
    method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/zip'},body:file,redirect:'error',cache:'no-store',credentials:'same-origin'
   });
   if(!response.ok){const body=await response.text();throw new Error(`HTTP ${response.status}: ${body.slice(0,240)}`)}
   if(action==='inventory'){const result=await response.json();byId('migration-report').textContent=JSON.stringify({inventory:result.data},null,2);message('Source inventory сохранён в PostgreSQL');}
   else {
    if(!response.headers.get('X-Migration-Manifest-SHA256'))throw new Error('Экспорт не содержит SHA-256 манифеста');
    const archive=await response.blob(),url=URL.createObjectURL(archive);
    try {const a=document.createElement('a');a.href=url;a.download=`gravit-source-${id}.zip`;document.body.appendChild(a);a.click();a.remove();}
    finally{URL.revokeObjectURL(url)}
    message('ZIP загружен. Архив содержит потенциально секретные данные.');
   }
  }catch(err){message(err.message,true)}finally{e.currentTarget.disabled=false}
 });
}

// MIG04: identity snapshots are persisted only after the 0.33.3 inventory.
for(const action of ['map-identities','verify-identities']) {
 byId('migration-'+action).addEventListener('click',async event=>{
  const id=migrationId(),file=byId('migration-assess').querySelector('[name=source]').files[0];
  if(!id||(action==='map-identities'&&(!file||file.size>512*1024*1024))){message('Выберите run и исходный ZIP до 512 MiB',true);return}
  const uri=`/api/v1/admin/migration-runs/${encodeURIComponent(id)}/identities`+(action==='verify-identities'?'/verify':'');
  event.currentTarget.disabled=true;
  try {
   const response=await fetch(uri,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':action==='map-identities'?'application/zip':'application/json'},body:action==='map-identities'?file:'{}',cache:'no-store',redirect:'error',credentials:'same-origin'});
   if(!response.ok)throw new Error(`HTTP ${response.status}: ${(await response.text()).slice(0,240)}`);
   const result=await response.json();byId('migration-report').textContent=JSON.stringify({identities:result.data},null,2);
   message('Карта UUID сверена. Cutover не разрешён.');
  }catch(e){message(e.message,true)}finally{event.currentTarget.disabled=false}
 });
}
