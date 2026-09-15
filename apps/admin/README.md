# NeverLauncher Admin UI 0.10.2

Admin UI — рабочая операторская панель NeverLauncher для канонического Backend API `/api/v1`.

## Назначение

- обзор состояния платформы;
- управление проектами, профилями и каналами;
- управление пользователями, ролями и правами;
- публикация пакетов и релизов;
- просмотр ServerBridge и состояния runtime;
- диагностика;
- операции резервного копирования и восстановления;
- аудит релизных и административных действий.

## Проверка

```bash
npm ci
npm run build
```

В составе общего preflight:

```bash
NEVERLAUNCHER_PREFLIGHT_FRONTEND=1 ./scripts/release/preflight.sh
```
