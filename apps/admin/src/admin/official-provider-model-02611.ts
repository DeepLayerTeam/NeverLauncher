export type OfficialProviderPolicy02611 = { clientId: string; enabled: boolean; browserEnabled: boolean; deviceEnabled: boolean; issuer: 'consumers' };
const uuid = /^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/i;
export const validProviderPolicy02611 = (v: OfficialProviderPolicy02611): boolean =>
  (!v.clientId || (uuid.test(v.clientId) && v.clientId.toLowerCase() !== '00000000-0000-0000-0000-000000000000')) &&
  (!v.enabled || (!!v.clientId && uuid.test(v.clientId) && (v.browserEnabled || v.deviceEnabled))) &&
  v.issuer === 'consumers';
