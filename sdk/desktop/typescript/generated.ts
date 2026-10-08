// Код сгенерирован scripts/sdk/generate-types.py; НЕ РЕДАКТИРОВАТЬ.
export const PROTOCOL_VERSION = 'neverextensions.desktop-rpc.v1' as const;
export const EXTENSION_API_VERSION = '1.0' as const;

export type DesktopContext = { extensionId: string; version: string; extensionApiVersion: string; scope: string; scopeId: string; pageId: string; actionId: string; bridgeAllowed: boolean };

export type RPCRequest = { protocol: typeof PROTOCOL_VERSION; type: 'rpc.request'; id: string; method: string; params: unknown };
export type RPCResponse = { protocol: typeof PROTOCOL_VERSION; type: 'rpc.response'; id: string; result?: unknown; error?: string };
