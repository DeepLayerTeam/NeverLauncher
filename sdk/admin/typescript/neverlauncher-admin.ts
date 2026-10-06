import { PROTOCOL_VERSION, type AdminContext, type RPCRequest } from './generated';
export { PROTOCOL_VERSION as NEVERLAUNCHER_ADMIN_PROTOCOL, EXTENSION_API_VERSION, type AdminContext } from './generated';

export type AdminSessionContext = Omit<AdminContext, 'pageId' | 'actionId'> & { generation:number; actor:{id:string;email:string} };

export type AdminRPCMethods = {
  'context.get': { params: Record<string, never>; result: AdminSessionContext };
  'projects.list': { params: Record<string, never>; result: Array<Record<string, unknown>> };
  'releases.list': { params: {projectId:string}; result: Array<Record<string, unknown>> };
  'audit.list': { params: Record<string, never>; result: Array<Record<string, unknown>> };
  'storage.info': { params: Record<string, never>; result: {driver:string} };
  'telemetry.emit': { params: {projectId:string;event:string;status?:string}; result: {accepted:boolean} };
};

type Pending = { resolve:(v:unknown)=>void; reject:(e:Error)=>void; timer:number };

export class NeverLauncherAdminBridge {
  private seq=0;
  private pending=new Map<string,Pending>();
  private closed=false;
  context:AdminContext|null=null;
  onAction:(actionId:string,pageId:string)=>void=()=>{};
  private listener:(event:MessageEvent)=>void;

  constructor(private readonly timeoutMs=10_000){
    this.listener=(event)=>{
      if(this.closed || event.source!==window.parent) return;
      const m=event.data as any;
      if(!m||m.protocol!==PROTOCOL_VERSION) return;
      if(m.type==='rpc.response'){
        const p=this.pending.get(String(m.id)); if(!p)return;
        this.pending.delete(String(m.id)); clearTimeout(p.timer);
        m.error?p.reject(new Error(String(m.error))):p.resolve(m.result);
      } else if(m.type==='host.context') this.context=m.context as AdminContext;
      else if(m.type==='host.action') this.onAction(String(m.actionId??''),String(m.pageId??''));
    };
    window.addEventListener('message',this.listener);
  }

  call<K extends keyof AdminRPCMethods>(method:K, params:AdminRPCMethods[K]['params']):Promise<AdminRPCMethods[K]['result']>{
    if(this.closed)return Promise.reject(new Error('NeverLauncher Admin bridge is closed'));
    const id=`rpc-${Date.now()}-${++this.seq}`;
    const msg:RPCRequest={protocol:PROTOCOL_VERSION,type:'rpc.request',id,method:String(method),params};
    window.parent.postMessage(msg,'*');
    return new Promise((resolve,reject)=>{
      const timer=window.setTimeout(()=>{this.pending.delete(id);reject(new Error('NeverLauncher Admin RPC timeout'))},this.timeoutMs);
      this.pending.set(id,{resolve:resolve as (v:unknown)=>void,reject,timer});
    });
  }

  close(){
    if(this.closed)return; this.closed=true; window.removeEventListener('message',this.listener);
    for(const [id,p] of this.pending){clearTimeout(p.timer);p.reject(new Error('NeverLauncher Admin bridge closed'));this.pending.delete(id)}
  }
}
