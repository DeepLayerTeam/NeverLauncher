// Разрешение запуска на конкретном сервере — отдельный шаг, не равный наличию учётных данных
// в хранилище ОС. Токены Microsoft bearer не должны проходить через этот интерфейс.
export type OfficialJoin0397 = {username: string; uuid: string; serverId: string};
export function assertOfficialJoin0397(result: OfficialJoin0397, expected: {uuid: string; name: string; serverId: string}): OfficialJoin0397 {
  const uuid=(v:string)=>v.replace(/-/g, '').toLowerCase();
  if (!result || !/^[a-f0-9]{32}$/.test(uuid(result.uuid)) || uuid(result.uuid)!==uuid(expected.uuid) ||
    !/^[a-zA-Z0-9_]{3,16}$/.test(result.username) || result.username!==expected.name ||
    result.serverId!==expected.serverId) {
    throw new Error('ServerBridge вернул другой официальный UUID Minecraft, имя игрока или сервер');
  }
  return result;
}
