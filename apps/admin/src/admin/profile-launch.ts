/** Validation shared by the profile editor and Admin regression tests. */
export interface ProfileLaunchForm0382 {
  id:string; name:string; minecraftVersion:string; loader:string; loaderVersion:string; javaMajor:number;
}
export function validateProfile0382(form:ProfileLaunchForm0382):string {
  if(!/^[a-z0-9][a-z0-9_.-]{0,63}$/.test(form.id) || form.id==='.' || form.id==='..')return 'ID: 1–64 символа, латинские строчные буквы, цифры, «.», «_», «-».';
  if(!form.name.trim() || form.name.length>120)return 'Название профиля обязательно (до 120 символов).';
  if(!/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/.test(form.minecraftVersion))return 'Укажите корректную версию Minecraft (например, 1.21.1).';
  if(!['vanilla','fabric','quilt','forge','neoforge'].includes(form.loader))return 'Неподдерживаемый загрузчик.';
  if(!Number.isInteger(form.javaMajor) || form.javaMajor<8 || form.javaMajor>255)return 'Java major должен быть от 8 до 255.';
  if(form.loader!=='vanilla' && !/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$/.test(form.loaderVersion))return 'Укажите точную версию загрузчика, не latest.';
  if(form.loader==='vanilla' && form.loaderVersion!=='')return 'Vanilla не использует версию загрузчика.';
  return '';
}
