# 구현 사양

## 프로젝트 구조

Go 구현 기준으로 아래 구조를 만든다.

```text
.
├── cmd/n8n-proxy/main.go
├── internal/config/config.go
├── internal/httpserver/server.go
├── internal/httpserver/routes.go
├── internal/oidc/client.go
├── internal/session/store.go
├── internal/vault/credential_store.go
├── internal/n8n/client.go
├── internal/proxy/reverse_proxy.go
├── internal/security/cookie.go
├── internal/security/csrf.go
├── internal/logging/logging.go
├── docs/
├── go.mod
└── Dockerfile
```

## Configuration

모든 설정은 environment variable로 받는다.

| Env | Required | Default | Description |
| --- | --- | --- | --- |
| `PUBLIC_BASE_URL` | yes | none | 프록시 public origin, 예: `https://n8n.example.com` |
| `N8N_UPSTREAM_URL` | yes | none | n8n internal origin, 예: `http://n8n:5678` |
| `OIDC_ISSUER_URL` | yes | none | OIDC issuer |
| `OIDC_CLIENT_ID` | yes | none | OIDC client id |
| `OIDC_CLIENT_SECRET` | yes | none | OIDC client secret |
| `OIDC_SCOPES` | no | `openid profile email` | Space-separated scopes |
| `REDIS_URL` | yes | none | Redis connection URL |
| `VAULT_ADDR` | yes | none | Vault address |
| `VAULT_TOKEN` | yes | none | Vault token, Kubernetes에서는 agent injection 권장 |
| `VAULT_KV_MOUNT` | no | `secret` | KV v2 mount |
| `VAULT_KV_PREFIX` | no | `n8n-gw/users` | credential path prefix |
| `SESSION_TTL` | no | `8h` | proxy session TTL |
| `OIDC_STATE_TTL` | no | `10m` | OAuth state TTL |
| `CONSOLE_PROXY_TIMEOUT` | no | `60s` | protected console/API request timeout |
| `PUBLIC_EXECUTION_TIMEOUT` | no | `300s` | webhook/form bypass timeout |
| `PUBLIC_BYPASS_PREFIXES` | no | built-in list | comma-separated bypass prefixes |
| `COOKIE_SECURE` | no | inferred from `PUBLIC_BASE_URL` | force Secure cookies |
| `TRUSTED_PROXY_CIDRS` | no | empty | trusted `X-Forwarded-*` source CIDRs |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error` |

## HTTP server middleware order

`server.go`는 아래 순서로 middleware를 적용한다.

1. request id 생성 또는 `X-Request-Id` 수용
2. trusted proxy header 정규화
3. panic recovery
4. structured access log
5. security headers
6. route dispatch

보안 헤더 기본값:

```text
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self'; frame-ancestors 'self'
```

n8n UI가 추가 asset source를 요구하면 CSP는 운영 환경에서 실제 브라우저 오류를 보고 조정한다.

## Route dispatch pseudocode

```go
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
    path := cleanPath(r.URL.Path)

    switch {
    case isInternalRoute(path):
        internalRouter.ServeHTTP(w, r)
        return

    case isPublicBypassRoute(path):
        publicExecutionProxy.ServeHTTP(w, r)
        return

    case isBlockedNativeLoginRoute(r.Method, path):
        http.NotFound(w, r)
        return

    default:
        requireProxySessionOrStartOIDC(w, r)
        ensureN8NSessionOrLogin(w, r)
        consoleProxy.ServeHTTP(w, r)
        return
    }
}
```

`isBlockedNativeLoginRoute`는 최소한 아래를 포함한다.

- `POST /rest/login`
- `GET /signin`
- `GET /login`

`GET /signin`/`GET /login`은 404보다 `/auth/login` redirect가 사용자 경험상 낫다. 단, `POST /rest/login`은 credential stuffing 시도를 줄이기 위해 404 또는 403을 반환한다.

## OIDC implementation

### GET `/auth/login`

입력:

- optional query `return_to`

동작:

1. `return_to`가 없으면 현재 referer가 아니라 `/`를 사용한다.
2. `return_to`는 same-origin relative path만 허용한다.
3. `state`, `nonce`, `code_verifier`를 생성한다.
4. Redis에 `oidc_state:{state}`로 저장한다.
5. OIDC authorization URL로 302 redirect한다.

Redis value:

```json
{
  "nonce": "base64url-random",
  "code_verifier": "base64url-random",
  "return_to": "/workflows",
  "created_at": "2026-06-14T00:00:00Z"
}
```

### GET `/auth/callback`

동작:

1. `state`를 Redis에서 조회하고 즉시 삭제한다.
2. authorization code를 token endpoint에서 교환한다.
3. ID token issuer, audience, expiry, nonce를 검증한다.
4. `{issuer, subject, email, name}`으로 proxy session을 생성한다.
5. Vault에서 n8n credential을 조회한다.
6. credential이 없으면 `/n8n-link`로 redirect한다.
7. credential이 있으면 `n8nLogin()`을 호출한다.
8. 성공 시 n8n `Set-Cookie`를 재작성해서 브라우저에 내려주고 `return_to`로 redirect한다.
9. 실패 시 Vault mapping은 유지하되 `/n8n-link?error=relink_required`로 redirect한다.

## Session store

Redis key:

- `session:{session_id}`

Session id:

- 32 bytes cryptographically secure random
- base64url without padding

Cookie:

```text
__Host-n8np_session=<session_id>; Path=/; Secure; HttpOnly; SameSite=Lax
```

`__Host-` prefix를 쓰려면 Domain attribute를 절대 넣지 않는다.

## Vault credential store

Vault KV v2 path:

```text
{VAULT_KV_MOUNT}/data/{VAULT_KV_PREFIX}/{issuer_hash}/{subject_hash}
```

`issuer_hash`와 `subject_hash`:

- `base64url(sha256(value))`
- path traversal 방지를 위해 원문 issuer/subject를 path에 넣지 않는다.

Stored JSON:

```json
{
  "issuer": "https://idp.example.com",
  "subject": "oidc-subject",
  "email": "user@example.com",
  "n8n_email_or_login_id": "n8n-user@example.com",
  "n8n_password": "plain-password-stored-in-vault",
  "linked_at": "2026-06-14T00:00:00Z",
  "updated_at": "2026-06-14T00:00:00Z"
}
```

로그에는 `n8n_password`를 절대 출력하지 않는다. Vault read/write wrapper는 secret fields를 redaction한 structured log만 남긴다.

## n8n client

### Login request

Endpoint:

```text
POST {N8N_UPSTREAM_URL}/rest/login
Content-Type: application/json
Accept: application/json
```

Body:

```json
{
  "emailOrLdapLoginId": "n8n-user@example.com",
  "password": "password"
}
```

성공 조건:

- HTTP 200
- 응답에 하나 이상의 `Set-Cookie`가 있어야 한다.

실패 처리:

- 400/401: invalid credential 또는 MFA 요구로 간주한다.
- 429: n8n rate limit으로 간주하고 사용자에게 잠시 후 재시도를 안내한다.
- 5xx/network: upstream 장애로 간주한다.

MFA:

- 자동 MFA 입력은 1차 범위에 포함하지 않는다.
- n8n response body에 MFA 관련 error code/message가 있으면 `mfa_required` 내부 에러로 매핑한다.

### Logout request

Endpoint:

```text
POST {N8N_UPSTREAM_URL}/rest/logout
```

브라우저가 보낸 n8n cookie를 upstream에 전달한다.

브라우저에서 들어온 `POST /rest/logout`은 n8n UI의 로그아웃 요청으로 간주한다. 이 경우 proxy session cookie는 삭제하지 않고, n8n bridge marker만 삭제한 뒤 `/`로 redirect한다. 사용자가 OIDC 인증 상태를 유지하고 있으면 다음 `/` 접근에서 Vault credential로 n8n 세션을 다시 만든다.

프록시 자체 로그아웃은 `POST /auth/logout`만 사용한다. 이 endpoint는 proxy session cookie와 n8n bridge marker를 삭제하고, n8n logout을 best-effort로 호출한다.

## Cookie rewrite

`Set-Cookie` 재작성 규칙:

1. cookie name/value는 변경하지 않는다.
2. `Domain` attribute는 제거한다.
3. `Path`가 없으면 `/`를 추가한다.
4. `Secure`는 HTTPS public base URL이면 강제한다.
5. `HttpOnly`는 있으면 유지하고, n8n session cookie에는 없더라도 추가하지 않는다. upstream 의도를 존중한다.
6. `SameSite`가 없으면 `Lax`를 추가한다.
7. `Expires`/`Max-Age`는 유지한다.

Go에서는 `net/http`의 `http.Cookie` parser가 일부 비표준 attribute를 버릴 수 있다. 구현 시 `Set-Cookie` header 문자열 parser를 직접 쓰거나 검증된 라이브러리를 사용하고, unknown attribute는 가능한 보존한다.

## Reverse proxy

### 공통 규칙

- upstream URL scheme/host로 request URL을 재작성한다.
- `Host` header는 `N8N_UPSTREAM_URL` host로 설정한다.
- 원래 host/proto는 `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-For`로 전달한다.
- request body는 buffering하지 않고 stream한다.
- response body도 stream한다.
- `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` hop-by-hop headers는 Go ReverseProxy 기본 정책에 맡기거나 명시 제거한다.
- WebSocket upgrade를 지원한다.

### Public execution proxy

webhook/form route는 아래 특성을 가진다.

- OIDC redirect 금지
- proxy session cookie 요구 금지
- n8n session cookie 요구 금지
- timeout: `PUBLIC_EXECUTION_TIMEOUT`
- body size limit은 기본 무제한으로 두지 말고 환경변수로 추가 가능하게 한다. 1차 기본값은 `50MiB`.
- response status/body/header를 가능한 그대로 보존한다.

### Console proxy

protected route는 아래 특성을 가진다.

- proxy session 필수
- n8n session 보장
- timeout: `CONSOLE_PROXY_TIMEOUT`
- n8n session이 없거나 만료된 것으로 보이면 Vault credential로 재로그인 후 원 요청을 재시도하지 않는다. 대신 login cookie를 내려주고 원 URL로 302 redirect한다. mutating request 재시도는 중복 실행 위험이 있다.

## `/n8n-link` UI

최소 UI만 구현한다. 별도 frontend framework는 쓰지 않는다.

GET 화면 요소:

- 현재 OIDC email/name 표시
- n8n 이메일 또는 login id input
- n8n password input
- 연결 버튼
- 기존 연결이 있으면 "재연결" 안내
- 연결 삭제 버튼

POST:

- `Content-Type: application/x-www-form-urlencoded`
- field:
  - `csrf_token`
  - `n8n_email_or_login_id`
  - `n8n_password`
- 성공: Vault 저장 후 `/` redirect
- 실패: 400 page with generic message

CSRF:

- proxy session별 CSRF token을 Redis에 저장하거나 signed token으로 발급한다.
- POST/DELETE는 CSRF 필수다.

## Error responses

사람용 protected route:

- OIDC 필요: 302 `/auth/login`
- 연결 필요: 302 `/n8n-link`
- n8n credential invalid: 302 `/n8n-link?error=relink_required`
- upstream 장애: 503 HTML

public execution route:

- upstream 장애: 502/504 plain text 또는 upstream style 유지
- 절대 OIDC redirect하지 않는다.

JSON API 호출:

- `Accept: application/json`이면 HTML 대신 JSON error를 반환한다.

예:

```json
{
  "error": "upstream_unavailable",
  "request_id": "req_..."
}
```
