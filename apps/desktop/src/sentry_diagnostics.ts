// Only frames pointing into this packaged app are sent. Never send messages, cookies,
// URLs, exception objects, usernames, auth tokens, or raw JS stack traces.
export type SafeFrame0309 = { asset: string; line: number; column: number };
const framePattern = /(?:^|[/(])assets\/([a-zA-Z0-9_.-]+\.js):(\d{1,8}):(\d{1,8})\b/g;
export function stackFrames0309(stack: unknown): SafeFrame0309[] {
  if (typeof stack !== 'string') return [];
  const frames: SafeFrame0309[] = [];
  for (const match of stack.slice(0, 8192).matchAll(framePattern)) {
    const line = Number(match[2]), column = Number(match[3]);
    if (line > 0 && column > 0) frames.push({ asset: `assets/${match[1]}`, line, column });
    if (frames.length >= 16) break;
  }
  return frames;
}
export type ErrorTransport0309 = (category: string, frames: SafeFrame0309[]) => void;
export function installErrorCapture0309(target: Pick<Window, 'addEventListener' | 'removeEventListener'>, transport: ErrorTransport0309): () => void {
  const onError = (ev: Event) => {
    const error = (ev as ErrorEvent).error;
    transport('desktop.js.uncaught', stackFrames0309(error instanceof Error ? error.stack : undefined));
  };
  const onRejection = (ev: Event) => {
    const reason = (ev as PromiseRejectionEvent).reason;
    transport('desktop.js.rejection', stackFrames0309(reason instanceof Error ? reason.stack : undefined));
  };
  target.addEventListener('error', onError);
  target.addEventListener('unhandledrejection', onRejection);
  return () => { target.removeEventListener('error', onError); target.removeEventListener('unhandledrejection', onRejection); };
}
