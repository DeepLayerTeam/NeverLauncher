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
