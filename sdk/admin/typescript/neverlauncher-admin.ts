export const NEVERLAUNCHER_ADMIN_PROTOCOL = 'neverextensions.admin-rpc.v1' as const;
export type AdminContext = { extensionId:string; version:string; scope:'global'|'project'; scopeId:string; pageId:string; actionId:string };
export type AdminRPCMethods = {
  'context.get': { params: Record<string, never>; result: AdminContext & { actor:{id:string;email:string} } };
  'projects.list': { params: Record<string, never>; result: Array<Record<string, unknown>> };
  'releases.list': { params: {projectId:string}; result: Array<Record<string, unknown>> };
  'audit.list': { params: Record<string, never>; result: Array<Record<string, unknown>> };
  'storage.info': { params: Record<string, never>; result: {driver:string} };
  'telemetry.emit': { params: {projectId:string;event:string;status?:string}; result: {accepted:boolean} };
};
type RpcRequest = { protocol:typeof NEVERLAUNCHER_ADMIN_PROTOCOL; type:'rpc.request'; id:string; method:string; params:unknown };
type RpcResponse = { protocol:typeof NEVERLAUNCHER_ADMIN_PROTOCOL; type:'rpc.response'; id:string; result?:unknown; error?:string };

export class NeverLauncherAdminBridge {
  private seq=0; private pending=new Map<string,{resolve:(v:any)=>void;reject:(e:Error)=>void}>();
  context:AdminContext|null=null;
  onAction:(actionId:string,pageId:string)=>void=()=>{};
  constructor(){ window.addEventListener('message',(event)=>{ if(event.source!==window.parent) return; const m=event.data as any; if(!m||m.protocol!==NEVERLAUNCHER_ADMIN_PROTOCOL)return; if(m.type==='rpc.response'){const p=this.pending.get(m.id);if(!p)return;this.pending.delete(m.id);m.error?p.reject(new Error(m.error)):p.resolve(m.result)} else if(m.type==='host.context'){this.context=m.context as AdminContext} else if(m.type==='host.action'){this.onAction(String(m.actionId??''),String(m.pageId??''))} }); }
  call<K extends keyof AdminRPCMethods>(method:K, params:AdminRPCMethods[K]['params']):Promise<AdminRPCMethods[K]['result']>{ const id=`rpc-${Date.now()}-${++this.seq}`; const msg:RpcRequest={protocol:NEVERLAUNCHER_ADMIN_PROTOCOL,type:'rpc.request',id,method:String(method),params}; window.parent.postMessage(msg,'*'); return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.pending.delete(id);reject(new Error('NeverLauncher Admin RPC timeout'))},10000);this.pending.set(id,{resolve:(v)=>{clearTimeout(timer);resolve(v)},reject:(e)=>{clearTimeout(timer);reject(e)}})}); }
}
