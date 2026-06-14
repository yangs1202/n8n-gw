# n8n-gw

OIDC gateway for n8n Community Edition.

`n8n-gw` is a reverse proxy that adds OIDC login to n8n Community Edition without patching n8n itself. Browser users authenticate with an OIDC provider, then the gateway maps that identity to an existing n8n account stored in Vault, performs the n8n UI login server-side, and forwards the resulting browser session to n8n.

Public execution endpoints such as webhooks and forms bypass OIDC so external services can continue calling n8n normally.

## Features

- OIDC authentication for n8n console access
- Vault-backed mapping from OIDC users to n8n credentials
- Server-side n8n `/rest/login` bridge
- Redis-backed gateway sessions and OIDC state
- Pass-through routing for `/webhook/*`, `/form/*`, and related public execution paths
- External `POST /rest/login` blocking
- Health and readiness endpoints
- Prometheus metrics

## Container Image

```bash
docker pull ghcr.io/yangs1202/n8n-gw:latest
docker pull ghcr.io/yangs1202/n8n-gw:v1.0
```

## Required Configuration

```bash
PUBLIC_BASE_URL=https://proxy.example.com
N8N_UPSTREAM_URL=http://n8n:5678
OIDC_ISSUER_URL=https://idp.example.com
OIDC_CLIENT_ID=n8n-gw
OIDC_CLIENT_SECRET=change-me
REDIS_URL=redis://redis:6379/0
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=change-me
```

Production deployments should prefer Vault AppRole instead of a long-lived Vault token:

```bash
VAULT_ROLE_ID=change-me
VAULT_SECRET_ID=change-me
```

Optional defaults:

```bash
OIDC_SCOPES="openid profile email"
VAULT_KV_MOUNT=secret
VAULT_KV_PREFIX=n8n-gw/users
PUBLIC_BYPASS_PREFIXES=/webhook/,/webhook-test/,/webhook-waiting/,/form/,/form-test/,/forms/,/forms-test/
```

## Local Run

Create a local `.env` file from the variables above, then run:

```bash
./scripts/run-local.sh
```

## Security Notes

- Do not expose the upstream n8n service directly to the public internet.
- Do not commit `.env`, Vault tokens, OIDC client secrets, AppRole IDs, AppRole secrets, Kubernetes manifests, private ingress details, or production hostnames to this repository.
- Public execution routes such as `/webhook/*` and `/form/*` bypass OIDC by design. Configure authentication at the n8n workflow or upstream edge layer when needed.
- External `POST /rest/login` requests are blocked by the gateway. Only the gateway's internal n8n client calls upstream n8n login.
- n8n `/rest/login` is an internal UI endpoint, not a stable public API. Re-test this bridge when upgrading n8n.

## Documentation

Implementation details are in [docs/README.md](docs/README.md).

---

# n8n-gw 한국어

n8n Community Edition을 수정하지 않고 OIDC 로그인을 붙이는 게이트웨이입니다.

`n8n-gw`는 n8n 앞단에 위치하는 reverse proxy입니다. 브라우저 사용자는 OIDC로 인증하고, 게이트웨이는 OIDC 사용자를 Vault에 저장된 기존 n8n 계정 정보와 매핑합니다. 그 다음 게이트웨이가 서버 사이드에서 n8n UI 로그인을 수행하고, 발급된 n8n 브라우저 세션을 사용자에게 전달합니다.

웹훅과 폼 같은 public execution endpoint는 OIDC로 리다이렉트하지 않고 그대로 n8n으로 전달합니다.

## 주요 기능

- n8n 콘솔 접근에 OIDC 인증 추가
- Vault 기반 OIDC 사용자와 n8n 계정 매핑
- 서버 사이드 n8n `/rest/login` 브리지
- Redis 기반 gateway session 및 OIDC state 저장
- `/webhook/*`, `/form/*` 등 public execution path 바이패스
- 외부 `POST /rest/login` 차단
- health/readiness endpoint 제공
- Prometheus metrics 제공

## 컨테이너 이미지

```bash
docker pull ghcr.io/yangs1202/n8n-gw:latest
docker pull ghcr.io/yangs1202/n8n-gw:v1.0
```

## 필수 설정

```bash
PUBLIC_BASE_URL=https://proxy.example.com
N8N_UPSTREAM_URL=http://n8n:5678
OIDC_ISSUER_URL=https://idp.example.com
OIDC_CLIENT_ID=n8n-gw
OIDC_CLIENT_SECRET=change-me
REDIS_URL=redis://redis:6379/0
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=change-me
```

운영 환경에서는 장기 Vault token보다 Vault AppRole 사용을 권장합니다.

```bash
VAULT_ROLE_ID=change-me
VAULT_SECRET_ID=change-me
```

## 보안 주의사항

- upstream n8n service를 public internet에 직접 노출하지 마세요.
- `.env`, Vault token, OIDC client secret, AppRole ID, AppRole secret, Kubernetes manifest, private ingress 정보, 운영 hostname을 repository에 commit하지 마세요.
- `/webhook/*`, `/form/*` 같은 public execution route는 의도적으로 OIDC를 우회합니다. 필요한 인증은 n8n workflow 또는 edge layer에서 설정하세요.
- 외부 `POST /rest/login`은 gateway가 차단합니다. upstream n8n login은 gateway 내부 client만 호출합니다.
- n8n `/rest/login`은 안정적인 public API가 아니라 UI 내부 endpoint입니다. n8n 업그레이드 시 반드시 integration test로 다시 확인하세요.

---

# n8n-gw 中文

用于 n8n Community Edition 的 OIDC 网关。

`n8n-gw` 是部署在 n8n 前面的反向代理。用户通过 OIDC 登录后，网关会把 OIDC 身份映射到 Vault 中保存的现有 n8n 账号和密码，然后在服务端调用 n8n UI 登录接口，并把生成的浏览器会话转发给用户。

Webhook、form 等公开执行路径不会触发 OIDC 重定向，因此外部服务可以继续正常调用 n8n。

## 功能

- 为 n8n 控制台访问添加 OIDC 认证
- 使用 Vault 保存 OIDC 用户到 n8n 账号的映射
- 服务端 n8n `/rest/login` 登录桥接
- 使用 Redis 保存网关会话和 OIDC state
- 直通 `/webhook/*`、`/form/*` 等公开执行路径
- 阻止外部 `POST /rest/login`
- 提供 health/readiness 接口
- 提供 Prometheus metrics

## 容器镜像

```bash
docker pull ghcr.io/yangs1202/n8n-gw:latest
docker pull ghcr.io/yangs1202/n8n-gw:v1.0
```

## 必需配置

```bash
PUBLIC_BASE_URL=https://proxy.example.com
N8N_UPSTREAM_URL=http://n8n:5678
OIDC_ISSUER_URL=https://idp.example.com
OIDC_CLIENT_ID=n8n-gw
OIDC_CLIENT_SECRET=change-me
REDIS_URL=redis://redis:6379/0
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=change-me
```

生产环境建议使用 Vault AppRole，而不是长期有效的 Vault token。

```bash
VAULT_ROLE_ID=change-me
VAULT_SECRET_ID=change-me
```

## 安全注意事项

- 不要把上游 n8n 服务直接暴露到公网。
- 不要提交 `.env`、Vault token、OIDC client secret、AppRole ID、AppRole secret、Kubernetes manifest、私有 ingress 信息或生产域名。
- `/webhook/*`、`/form/*` 等公开执行路径会有意绕过 OIDC。需要认证时，请在 n8n workflow 或边缘网关层配置。
- 外部 `POST /rest/login` 会被网关阻止。只有网关内部的 n8n client 会调用上游 n8n 登录接口。
- n8n `/rest/login` 是 UI 内部接口，不是稳定的公开 API。升级 n8n 时必须重新运行集成测试。
