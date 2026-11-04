# Launcher 0.25.8 — Desktop Textures UI

## What ships

**Desktop → Скины и плащи** is a real React UI, integrated into the existing app navigation and Launcher session lifecycle (not an iframe, stub or mock backend). It consumes the previously deployed 0.25.1–0.25.7 backend texture APIs and separates two identities:

- **Локальный Launcher:** uses the authenticated Never session and its server-owned canonical Minecraft UUID. Saved library (12 images per page), selected texture, revision, gallery previews, selecting an existing PNG, uploading/importing, reset/delete, model and visibility changes, history and permission-error feedback.
- **Официальный Minecraft:** uses only the Microsoft account explicitly linked in **Вход** and the existing official Minecraft Services gateway. Uploads official skins, selects only owned official capes, resets skins/capes and retrieves the current official profile. Neither the local UUID nor local texture blob IDs are forwarded to official services. The official session is scoped to Never session and cleared on logout.

The preview renders the classic/slim Minecraft avatar with the actual Java skin-atlas UV layout, including 64x64 overlay layers. In **3D**, 3D-transformed textured cubes provide live orbit via pointer drag, with cape behind the avatar and front/back/side faces; **2D** uses a flat front projection, plus a separate 2D cape preview. Pixel-art rendering uses `image-rendering: pixelated`. There are no additional runtime libraries. Higher-resolution skins preserve original UV proportions. This visual-only client renderer does not replace validating/uploading the full PNG on the server.

Owner-only gallery PNGs are fetched with the authenticated Bearer token; temporary `blob:` object URLs are revoked on preview/gallery unmount or when the selection changes. 12 images are loaded per page. The frontend never embeds the Never token in an image URL. Official skins are displayed only from `textures.minecraft.net` paths `/texture/<hash>` with canonical HTTPS, allowed explicitly in Tauri's CSP. No arbitrary user-supplied external image URL becomes a browser preview source.

## Behavior

1. Open Desktop and log in to Launcher using **Вход**.
2. Open **Скины и плащи**. Select local or official identity explicitly; local identity never switches the selected launch identity in the background.
3. Choose **Скины** or **Плащи**. Upload a PNG (up to 4 MiB), choose classic/slim (skin only), or select a previously saved asset; the server validates format and Minecraft geometry. Import via external HTTPS is executed by the existing server-side SSRF-safe fetcher.
4. Observe upload progress and errors. Local requests include `expectedRevision` for CAS and refresh both selection and library after mutations; HTTP 409 refreshes current state without unsafe automatic retry.
5. Rotate the 3D preview with the pointer or switch to 2D; view the library and revision history. **Сбросить** removes the assignment but retains the saved PNG. **Удалить** removes the library entry (and resets first when currently active), after a confirmation.
6. For official identities, connect Microsoft in **Вход**, then upload official skin / select owned official cape / reset. Official capes cannot be uploaded. The button **Обновить** re-fetches the official profile.

## Launch and test

Backend must already be upgraded through 0.25.7 with working PostgreSQL migrations and configured local/S3 texture storage. Without a configured public texture base URL, Minecraft may not be able to see an assigned locally stored texture even if Desktop previews work. See `texture-service-0255.md`, `yggdrasil-authlib-injector-0256.md`, `official-minecraft-0257.md`.

```bash
cd apps/desktop
npm ci
npm run build               # TypeScript strict + Vite release build
npm run test:textures       # API client, ownership separation, CAS, 401/409, private PNG, progress, official rotation
npm run tauri:build         # requires platform-specific Tauri dependencies
```

CI's `web` job runs both frontend build and `test:textures`. In an offline container without the npm tarballs, only the pure TypeScript client tests can run through a globally installed `tsc`; full Tauri/browser verification must then be recorded as **not executed**, not silently considered a pass. For production certification, additionally test real local and S3 storage, upload/reset with server-side capes policy, login refresh/logoff, 3D preview across 64/128/256 skins, and appearance in a real Minecraft client with authlib-injector and in an official session.

This stage is Desktop UI only; it does not add database migrations or alter existing backend texture semantics. Admin entitlements and operational controls follow in 0.25.9.
