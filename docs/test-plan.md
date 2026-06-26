# 테스트 계획

## 테스트 레벨

1. Unit test
2. Integration test with fake OIDC/Vault/n8n
3. Docker compose end-to-end test
4. Manual browser verification

## Unit tests

### Route classifier

Cases:

- `GET /auth/login` -> internal
- `GET /auth/callback` -> internal
- `GET /n8n-link` -> internal protected
- `POST /webhook/foo` -> public execution
- `GET /webhook-test/foo` -> public execution
- `POST /webhook-waiting/foo` -> public execution
- `GET /form/foo` -> public execution
- `POST /form-test/foo` -> public execution
- `GET /forms/foo` -> public execution
- `POST /forms-test/foo` -> public execution
- `POST /rest/login` -> blocked native login
- `GET /signin` -> native login alias
- `GET /workflows` -> protected console

Edge cases:

- `/webhook` without trailing slash should match if n8n supports it; otherwise redirect to `/webhook/` must not happen automatically.
- URL encoded path must not bypass classifier.
- `//rest/login`, `/rest/../rest/login` must normalize to blocked route.

### Cookie rewrite

Input:

```text
n8n-auth=abc; Domain=n8n.internal; Path=/; HttpOnly; SameSite=None
```

Expected:

```text
n8n-auth=abc; Path=/; HttpOnly; Secure; SameSite=None
```

More cases:

- no Domain -> no Domain
- no Path -> `Path=/`
- no SameSite -> `SameSite=Lax`
- Max-Age and Expires preserved
- unknown attributes preserved when possible

### Return URL validation

Allowed:

- `/`
- `/workflows`
- `/workflow/123?foo=bar`

Rejected:

- `https://evil.example.com`
- `//evil.example.com`
- `/\evil`
- control characters

### Vault path hashing

Verify:

- issuer/subject 원문이 path에 포함되지 않는다.
- 같은 issuer/subject는 같은 path를 만든다.
- 다른 issuer 또는 subject는 다른 path를 만든다.

### Redaction

Structured log redactor는 아래 key를 마스킹한다.

- `password`
- `n8n_password`
- `authorization`
- `cookie`
- `set-cookie`
- `id_token`
- `access_token`
- `refresh_token`
- `code`

## Integration tests

Fake services를 사용한다.

### Fake OIDC

기능:

- discovery endpoint
- authorization endpoint
- token endpoint
- JWKS endpoint
- configurable claims

Test:

1. `/auth/login`이 fake authorization endpoint로 redirect한다.
2. callback에서 state/nonce가 검증된다.
3. 잘못된 state는 400이다.
4. 잘못된 nonce/id token audience/issuer는 401이다.

### Fake Vault

가능하면 dev Vault container를 사용한다. 빠른 test는 in-memory interface 구현체를 쓴다.

Test:

1. credential missing이면 `/n8n-link`로 간다.
2. credential present이면 n8n login을 호출한다.
3. link 성공 시 Vault에 저장한다.
4. link 실패 시 Vault에 저장하지 않는다.
5. delete link 시 Vault secret을 삭제한다.

### Fake n8n

Fake n8n endpoints:

- `POST /rest/login`
- `POST /rest/logout`
- `GET /rest/login`
- `ANY /webhook/{path}`
- `ANY /webhook-test/{path}`
- `ANY /form/{path}`
- `GET /workflows`

Test:

1. proxy server-to-server login은 `/rest/login`에 JSON `emailOrLdapLoginId/password`를 보낸다.
2. fake n8n `Set-Cookie`가 브라우저 응답에 재작성된다.
3. 외부 `POST /rest/login`은 fake n8n에 도달하지 않는다.
4. `/webhook/foo`는 proxy session 없이 fake n8n에 도달한다.
5. `/webhook/foo`는 fake n8n 401/404/500을 그대로 반환한다.
6. protected `/workflows`는 proxy session이 없으면 OIDC로 redirect한다.
7. protected `/workflows`는 session과 n8n cookie가 있으면 upstream으로 통과한다.

## Docker compose E2E

Compose services:

- n8n-proxy
- n8n
- redis
- vault dev server
- fake OIDC or Keycloak

Scenarios:

### First link

1. Browser opens `/`.
2. OIDC login completes.
3. User lands on `/n8n-link`.
4. User enters valid n8n credential.
5. Browser receives n8n cookie for proxy domain.
6. Browser lands on n8n editor.

### Existing link

1. Vault already has credential.
2. Browser opens `/`.
3. OIDC login completes.
4. Proxy calls n8n `/rest/login`.
5. Browser lands on n8n editor without seeing `/n8n-link`.

### Invalid stored credential

1. Vault has wrong password.
2. OIDC login completes.
3. n8n login fails.
4. Browser lands on `/n8n-link?error=relink_required`.

### Direct native login blocked

```bash
curl -i -X POST https://proxy.example.com/rest/login \
  -H 'Content-Type: application/json' \
  -d '{"emailOrLdapLoginId":"x","password":"y"}'
```

Expected:

- 404 or 403
- fake/real n8n access log has no `/rest/login` hit from this request

### Webhook bypass

```bash
curl -i -X POST https://proxy.example.com/webhook/test-path \
  -H 'Content-Type: application/json' \
  -d '{"ok":true}'
```

Expected:

- no redirect to OIDC
- response is n8n workflow response or n8n 404 if workflow missing
- request body reaches n8n

### Form bypass

```bash
curl -i https://proxy.example.com/form/some-form
```

Expected:

- no redirect to OIDC
- response is n8n form response or n8n 404 if missing

## Manual browser verification

Chrome devtools에서 확인한다.

1. `__Host-n8np_session` cookie exists, Secure, HttpOnly, SameSite=None, Path=/, no Domain. Local HTTP mode uses `n8np_session` with SameSite=Lax.
2. n8n auth cookie exists on proxy host, not upstream host.
3. `/rest/login` does not appear as browser-originated request during normal login except blocked attempts. Proxy server-side call은 browser network panel에 보이면 안 된다.
4. Refresh after login keeps n8n editor session.
5. n8n UI logout keeps the proxy session, clears the n8n bridge marker, and re-enters the console on the next `/` request.
6. Proxy logout through `/auth/logout` clears both proxy session and n8n session.
7. Opening a webhook URL in private browser does not redirect to OIDC.

## Upgrade compatibility test

n8n version을 올릴 때마다 아래를 반드시 실행한다.

1. `POST /rest/login` payload field가 여전히 `emailOrLdapLoginId/password`인지 확인한다.
2. login success response에 `Set-Cookie`가 있는지 확인한다.
3. `GET /rest/login`이 current user check 용도로 동작하는지 확인한다.
4. webhook/form path prefix가 바뀌지 않았는지 확인한다.
5. MFA enabled user의 실패 응답이 기존 error mapping과 호환되는지 확인한다.

이 테스트가 실패하면 프록시를 배포하지 않는다.
