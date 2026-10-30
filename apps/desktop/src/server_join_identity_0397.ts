// Server-bound launch authorization is a separate step from possession of
// credentials in the OS vault. No Microsoft bearer may cross this interface.
export type OfficialJoin0397 = {username: string; uuid: string; serverId: string};
export function assertOfficialJoin0397(result: OfficialJoin0397, expected: {uuid: string; name: string; serverId: string}): OfficialJoin0397 {
  const uuid=(v:string)=>v.replace(/-/g, '').toLowerCase();
  if (!result || !/^[a-f0-9]{32}$/.test(uuid(result.uuid)) || uuid(result.uuid)!==uuid(expected.uuid) ||
    !/^[a-zA-Z0-9_]{3,16}$/.test(result.username) || result.username!==expected.name ||
    result.serverId!==expected.serverId) {
    throw new Error('ServerBridge returned a different official Minecraft UUID, name or server');
  }
  return result;
}
