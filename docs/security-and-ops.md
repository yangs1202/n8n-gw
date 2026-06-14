# 보안 및 운영

## Threat model

주요 위협은 아래다.

- OIDC를 우회한 n8n 콘솔 접근
- 외부에서 n8n `/rest/login` 직접 호출
- Vault에 저장된 n8n password 유출
- proxy log를 통한 token/cookie/credential 유출
- webhook 호출이 OIDC redirect를 받아 외부 연동이 장애나는 문제
- n8n session cookie domain/path 오류로 인한 세션 고정 또는 로그인 실패
- mutating request 자동 재시도로 인한 workflow 중복 변경

## 보안 정책

### n8n upstream 격리

- n8n upstream은 public internet에 직접 노출하지 않는다.
- n8n upstream service는 proxy에서만 접근 가능해야 한다.
- 운영자 native login은 VPN/private ingress/bastion 등 별도 경로로 제한한다.

### `/rest/login` 차단

외부 inbound `POST /rest/login`은 반드시 차단한다. 프록시 내부 n8n client만 upstream `/rest/login`을 호출한다.

권장 응답:

- 404: endpoint 존재를 숨김
- 또는 403: 운영 디버깅이 쉬움

운영 기본값은 404다.

### Vault ACL

프록시 Vault token은 아래 권한만 가진다.

```hcl
path "secret/data/n8n-gw/users/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/n8n-gw/users/*" {
  capabilities = ["read", "delete"]
}
```

list 권한은 기본적으로 주지 않는다. 운영자가 전체 연결 목록이 필요하면 별도 admin tooling으로 구현한다.

### Logging redaction

아래 값은 로그에 남기지 않는다.

- `password`
- `n8n_password`
- `Authorization`
- `Cookie`
- `Set-Cookie`
- OIDC authorization code
- access token
- refresh token
- id token
- CSRF token

Access log에 남길 필드:

- request id
- method
- path template 또는 raw path에서 query 제거
- status
- duration
- route class: `internal`, `public_execution`, `blocked_native_login`, `protected_console`
- upstream status
- user hash: `sha256(issuer + subject)` 앞 12자리

## Webhook/form 운영 정책

public execution route는 인증을 프록시가 담당하지 않는다. 대신 n8n workflow에서 필요한 인증을 설정한다.

권장:

- Webhook node 자체 인증 옵션 사용
- shared secret header 사용
- 예측 불가능한 webhook path 사용
- 외부 provider IP allowlist가 필요하면 L7 LB/WAF에서 처리

프록시는 public execution route에서 아래를 하지 않는다.

- OIDC redirect
- HTML login page 반환
- proxy session 생성
- n8n 자동 로그인
- request body 변환

## Timeouts

서로 다른 timeout profile을 둔다.

| Profile | Default | Applies to |
| --- | --- | --- |
| console | 60s | n8n UI, `/rest/*`, assets |
| public_execution | 300s | webhook/form |
| oidc | 10s | IdP token/userinfo requests |
| vault | 5s | Vault read/write |
| redis | 2s | session/state |

webhook이 장시간 대기하는 workflow를 쓰는 경우 `PUBLIC_EXECUTION_TIMEOUT`을 늘린다. 단, load balancer timeout도 함께 맞춰야 한다.

## Health checks

### `GET /healthz`

프로세스 생존만 확인한다.

응답:

```json
{ "ok": true }
```

### `GET /readyz`

아래 dependency를 확인한다.

- Redis ping
- Vault token lookup 또는 lightweight read capability check
- n8n upstream `GET /healthz` 또는 `/` best-effort
- OIDC discovery cache 존재. 시작 시 discovery 실패면 not ready.

응답:

```json
{
  "ok": true,
  "checks": {
    "redis": "ok",
    "vault": "ok",
    "n8n": "ok",
    "oidc": "ok"
  }
}
```

## Metrics

Prometheus endpoint `GET /metrics`를 제공한다.

필수 metric:

- `n8n_proxy_requests_total{route_class,status}`
- `n8n_proxy_request_duration_seconds{route_class}`
- `n8n_proxy_oidc_login_total{result}`
- `n8n_proxy_n8n_login_total{result}`
- `n8n_proxy_vault_operations_total{operation,result}`
- `n8n_proxy_public_execution_inflight`
- `n8n_proxy_upstream_errors_total{route_class}`

## Rollout checklist

1. n8n upstream이 public에서 직접 접근되지 않는지 확인한다.
2. `PUBLIC_BASE_URL`이 n8n의 external URL 설정과 일치하는지 확인한다.
3. OIDC redirect URI에 `{PUBLIC_BASE_URL}/auth/callback`을 등록한다.
4. Vault policy를 최소 권한으로 적용한다.
5. Redis persistence/HA 정책을 결정한다.
6. `/webhook/*`가 OIDC 없이 404 또는 workflow response를 반환하는지 확인한다.
7. `/rest/login` 외부 POST가 n8n으로 전달되지 않는지 확인한다.
8. `/n8n-link`에서 잘못된 n8n 비밀번호가 Vault에 저장되지 않는지 확인한다.
9. n8n cookie가 proxy host에 저장되는지 브라우저 devtools로 확인한다.
10. n8n UI logout(`/rest/logout`, `/signout`) 후 proxy session은 유지되고 n8n bridge marker만 제거되는지 확인한다.
11. proxy logout(`/auth/logout`) 후 proxy session과 n8n session이 모두 제거되는지 확인한다.

## Known limitations

- n8n internal `/rest/login`은 public API가 아니다. n8n 버전 업그레이드 시 integration test로 계약을 확인해야 한다.
- n8n MFA 계정의 자동 로그인은 1차 범위에서 제외한다.
- n8n password를 Vault에 저장하는 구조이므로, OIDC와 n8n 계정 생명주기가 어긋날 수 있다. 사용자가 퇴사/비활성화되면 OIDC 접근 차단과 Vault mapping 삭제 정책을 함께 운영해야 한다.
- n8n 계정 비밀번호가 변경되면 사용자는 `/n8n-link`에서 재연결해야 한다.
