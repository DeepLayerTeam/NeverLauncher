import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const configDir = fileURLToPath(new URL('.', import.meta.url));
const version = process.env.NEVERLAUNCHER_VERSION?.trim() || readFileSync(resolve(configDir, '../../VERSION'), 'utf8').trim();

export default defineConfig({
  plugins: [react()],
  define: {
    __NEVERLAUNCHER_VERSION__: JSON.stringify(version),
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true
  },
  envPrefix: ['VITE_', 'TAURI_']
});
