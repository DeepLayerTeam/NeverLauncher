import React, {useState, useRef} from 'react';
import type {SkinModel0258} from './texture_service_0258';

type Vec = {x:number;y:number;w:number;h:number};
type Cube = {id:string;x:number;y:number;z:number;w:number;h:number;d:number;atlas:Vec;overlay?:boolean; cape?:boolean};
const UNIT = 7;
// Java edition 64x64 skin atlas. Coordinates are the native Minecraft UV mapping;
// an HD skin is rendered at the same pixel-art aspect ratio without resampling.
function cubes0258(model: SkinModel0258): Cube[] {
  const arm = model === 'slim' ? 3 : 4;
  const base: Cube[] = [
    {id:'head',x:0,y:-12,z:0,w:8,h:8,d:8,atlas:{x:0,y:0,w:8,h:8}},
    {id:'body',x:0,y:-2,z:0,w:8,h:12,d:4,atlas:{x:16,y:16,w:8,h:12}},
    {id:'right-arm',x:-4-arm/2,y:-2,z:0,w:arm,h:12,d:4,atlas:{x:40,y:16,w:arm,h:12}},
    {id:'left-arm',x:4+arm/2,y:-2,z:0,w:arm,h:12,d:4,atlas:{x:32,y:48,w:arm,h:12}},
    {id:'right-leg',x:-2,y:10,z:0,w:4,h:12,d:4,atlas:{x:0,y:16,w:4,h:12}},
    {id:'left-leg',x:2,y:10,z:0,w:4,h:12,d:4,atlas:{x:16,y:48,w:4,h:12}},
  ];
  const overlay = [
    {id:'hat', index:0, atlas:{x:32,y:0,w:8,h:8}},
    {id:'jacket', index:1, atlas:{x:16,y:32,w:8,h:12}},
    {id:'right-sleeve',index:2,atlas:{x:40,y:32,w:arm,h:12}},
    {id:'left-sleeve',index:3,atlas:{x:48,y:48,w:arm,h:12}},
    {id:'right-pants',index:4,atlas:{x:0,y:32,w:4,h:12}},
    {id:'left-pants',index:5,atlas:{x:0,y:48,w:4,h:12}},
  ];
  return [...base, ...overlay.map(o=>({...base[o.index],id:o.id,overlay:true,atlas:o.atlas,w:base[o.index].w+.2,h:base[o.index].h+.2,d:base[o.index].d+.2}))];
}
const faceLayout: Array<{side:string;crop:(c:Cube)=>Vec;transform:(c:Cube)=>string;w:(c:Cube)=>number;h:(c:Cube)=>number}> = [
  {side:'front',crop:c=>({x:c.atlas.x+Math.round(c.d),y:c.atlas.y+Math.round(c.d),w:c.atlas.w,h:c.atlas.h}),transform:c=>`translate(-50%, -50%) translateZ(${c.d*UNIT/2}px)`,w:c=>c.w,h:c=>c.h},
  {side:'back',crop:c=>({x:c.atlas.x+Math.round(c.d)*2+Math.round(c.w),y:c.atlas.y+Math.round(c.d),w:c.atlas.w,h:c.atlas.h}),transform:c=>`translate(-50%, -50%) rotateY(180deg) translateZ(${c.d*UNIT/2}px)`,w:c=>c.w,h:c=>c.h},
  {side:'right',crop:c=>({x:c.atlas.x,y:c.atlas.y+Math.round(c.d),w:Math.round(c.d),h:c.atlas.h}),transform:c=>`translate(-50%, -50%) rotateY(90deg) translateZ(${c.w*UNIT/2}px)`,w:c=>c.d,h:c=>c.h},
  {side:'left',crop:c=>({x:c.atlas.x+Math.round(c.d)+Math.round(c.w),y:c.atlas.y+Math.round(c.d),w:Math.round(c.d),h:c.atlas.h}),transform:c=>`translate(-50%, -50%) rotateY(-90deg) translateZ(${c.w*UNIT/2}px)`,w:c=>c.d,h:c=>c.h},
  {side:'top',crop:c=>({x:c.atlas.x+Math.round(c.d),y:c.atlas.y,w:c.atlas.w,h:Math.round(c.d)}),transform:c=>`translate(-50%, -50%) rotateX(90deg) translateZ(${c.h*UNIT/2}px)`,w:c=>c.w,h:c=>c.d},
  {side:'bottom',crop:c=>({x:c.atlas.x+Math.round(c.d)+Math.round(c.w),y:c.atlas.y,w:c.atlas.w,h:Math.round(c.d)}),transform:c=>`translate(-50%, -50%) rotateX(-90deg) translateZ(${c.h*UNIT/2}px)`,w:c=>c.w,h:c=>c.d},
];
const cape0258: Cube = {id:'cape',x:0,y:-2,z:-4.5,w:10,h:16,d:1,atlas:{x:0,y:0,w:10,h:16},cape:true};

function uvStyle0258(url: string, crop: Vec, cape: boolean): React.CSSProperties {
  return {backgroundImage:`url(${JSON.stringify(url)})`,backgroundPosition:`-${crop.x*UNIT}px -${crop.y*UNIT}px`,backgroundSize:`${64*UNIT}px ${ (cape ? 32 : 64)*UNIT}px`,imageRendering:'pixelated'};
}
function Sprite0258({cube,url,view}: {cube:Cube;url:string;view:'2d'|'3d'}) {
  const adjusted: Cube = cube.overlay ? {...cube,w:cube.w,h:cube.h,d:cube.d} : cube;
  if (view === '2d') {
    // A literal front elevation rather than an atlas thumbnail.
    const crop = cube.cape ? {x:1,y:1,w:10,h:16} : faceLayout[0].crop(cube);
    return <div className="textureSprite0258" style={{left:`calc(50% + ${(cube.x-cube.atlas.w/2)*UNIT}px)`,top:`calc(50% + ${(cube.y-cube.atlas.h/2)*UNIT}px)`,width:cube.atlas.w*UNIT,height:cube.atlas.h*UNIT,...uvStyle0258(url,crop,Boolean(cube.cape))}} />;
  }
  return <div className="textureCube0258" style={{left:`calc(50% + ${(adjusted.x-adjusted.w/2)*UNIT}px)`,top:`calc(50% + ${(adjusted.y-adjusted.h/2)*UNIT}px)`,width:adjusted.w*UNIT,height:adjusted.h*UNIT,transform:`translateZ(${adjusted.z*UNIT}px)`}}>
    {faceLayout.map(f=>{const uv=f.crop(cube);return <div className="textureFace0258" key={f.side} style={{width:f.w(adjusted)*UNIT,height:f.h(adjusted)*UNIT,transform:f.transform(adjusted),...uvStyle0258(url,uv,Boolean(cube.cape))}}/>;})}
  </div>;
}
export function TexturePreview0258({skin,cape,model='classic'}:{skin?:string;cape?:string;model?:SkinModel0258}) {
  const [mode,setMode]=useState<'2d'|'3d'>('3d');
  const [yaw,setYaw]=useState(-24);
  const [pitch,setPitch]=useState(-12);
  const drag=useRef<{x:number;y:number;yaw:number;pitch:number}|null>(null);
  const cubes=cubes0258(model);
  const start=(e:React.PointerEvent<HTMLDivElement>)=>{
    if(mode==='2d')return;
    drag.current={x:e.clientX,y:e.clientY,yaw,pitch};e.currentTarget.setPointerCapture(e.pointerId);
  };
  const move=(e:React.PointerEvent<HTMLDivElement>)=>{
    if(!drag.current || mode==='2d')return;
    setYaw(drag.current.yaw + (e.clientX-drag.current.x)*.7);
    setPitch(Math.max(-65,Math.min(65,drag.current.pitch-(e.clientY-drag.current.y)*.4)));
  };
  return <section className="texturePreview0258" aria-label="Предпросмотр персонажа">
    <div className="texturePreviewToolbar0258">
      <strong>Предпросмотр</strong>
      <div role="group" aria-label="Режим просмотра"><button type="button" className={mode==='2d'?'active':''} onClick={()=>setMode('2d')}>2D</button><button type="button" className={mode==='3d'?'active':''} onClick={()=>setMode('3d')}>3D</button><button type="button" disabled={mode!=='3d'} onClick={()=>{setYaw(-24);setPitch(-12);}}>Сбросить вид</button></div>
    </div>
    <div className={'textureStage0258 '+(mode==='3d'?'three':'flat')} onPointerDown={start} onPointerMove={move} onPointerUp={()=>{drag.current=null;}} onPointerCancel={()=>{drag.current=null;}}>
      {!skin && !cape && <span className="textureEmpty0258">Выберите или загрузите скин для просмотра</span>}
      {skin && <div className="textureCharacter0258" style={{transform: mode==='3d'?`rotateX(${pitch}deg) rotateY(${yaw}deg)`:'none'}}>
        {cubes.map(c=><Sprite0258 key={c.id} cube={c} url={skin} view={mode}/>)}
        {cape && mode==='3d' && <Sprite0258 cube={cape0258} url={cape} view={mode}/>}
      </div>}
      {!skin&&cape&&mode==='3d'&&<div className="textureCharacter0258" style={{transform:`rotateX(${pitch}deg) rotateY(${yaw}deg)`}}><Sprite0258 cube={cape0258} url={cape} view={mode}/></div>}
      {cape && mode==='2d' && <div className="textureCapeSwatch0258"><span>Плащ</span><div style={{width:10*UNIT,height:16*UNIT,...uvStyle0258(cape,{x:1,y:1,w:10,h:16},true)}}/></div>}
    </div>
    <small>{mode==='3d'?'Потяните мышью для вращения модели.':'Фронтальная проекция, пиксели без сглаживания.'} · {model === 'slim' ? 'Slim (Alex)' : 'Classic (Steve)'}</small>
  </section>;
}
