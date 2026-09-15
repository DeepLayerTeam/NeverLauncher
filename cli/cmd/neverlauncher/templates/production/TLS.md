# TLS-развёртывание NeverLauncher 0.10.7

Публичный NeverLauncher ОБЯЗАН завершать TLS до попадания трафика во внутренний HTTP-only Compose ingress. Стандартный Compose намеренно публикует только HTTP и рассчитан на размещение за TLS-capable load balancer, ingress controller, Caddy, Traefik, облачным HTTPS load balancer или host Nginx.

## Обязательная схема

```text
Интернет
  -> TLS-терминатор (HTTPS :443, HTTP :80 только для redirect)
  -> NeverLauncher nginx :80
  -> Admin / API
```

Задайте `NEVERLAUNCHER_PUBLIC_URL=https://launcher.example.com` и передавайте исходную схему через `X-Forwarded-Proto: https`. Внутренний API доверяет forwarded-адресам только от фиксированной Compose-подсети `172.30.10.0/24`; не публикуйте порт API-контейнера напрямую в Интернет.

## Базовые требования TLS

Используйте TLS 1.2+ с предпочтением TLS 1.3, автоматически обновляемый сертификат, redirect HTTP -> HTTPS и HSTS на публичном TLS-терминаторе:

```nginx
server {
    listen 80;
    server_name launcher.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name launcher.example.com;
    ssl_certificate     /etc/letsencrypt/live/launcher.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/launcher.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_request_buffering off;
    }
}
```

При использовании host TLS-терминатора публикуйте Compose ingress только на loopback: `NEVERLAUNCHER_HTTP_PORT=127.0.0.1:8080`. Compose развернёт это в `127.0.0.1:8080:80`, поэтому внутренний ingress не будет доступен извне.

## Проверка

После развёртывания:

```bash
curl -fsS https://launcher.example.com/health
curl -fsS https://launcher.example.com/ready
curl -I https://launcher.example.com/
```

Не публикуйте БД, Redis, порт 8080 API-контейнера и токены Minecraft ServerBridge на публичных listeners.
