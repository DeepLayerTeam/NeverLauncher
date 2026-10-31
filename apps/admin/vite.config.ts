import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const configDir = fileURLToPath(new URL(".", import.meta.url));
const version =
  process.env.LAUNCHER_VERSION?.trim() ||
  readFileSync(resolve(configDir, "../../VERSION"), "utf8").trim();

export default defineConfig({
  plugins: [react()],
  define: {
    __LAUNCHER_VERSION__: JSON.stringify(version),
    __LAUNCHER_SOURCE_COMMIT__: JSON.stringify(
      /^[a-f0-9]{40}$/.test(process.env.LAUNCHER_SOURCE_COMMIT ?? "")
        ? process.env.LAUNCHER_SOURCE_COMMIT
        : "unknown",
    ),
  },
  server: {
    port: 5174,
  },
});
