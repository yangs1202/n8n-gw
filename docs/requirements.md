# 요구사항

## 목적

n8n Free/Community 버전 앞단에 OIDC 인증 프록시를 둔다. 사용자는 회사/조직 OIDC로 로그인하고, 프록시는 사용자의 OIDC identity와 미리 연결된 n8n 계정으로 n8n에 대신 로그인한다.

이 프로젝트의 목표는 n8n SSO 기능을 재구현하는 것이 아니라, n8n 웹 콘솔 접근에 한해 OIDC 인증을 강제하고 n8n 기존 세션 쿠키를 브라우저에 내려주는 것이다.

## 사용자 시나리오

### 1. 최초 계정 연결

1. 사용자가 `https://proxy.example.com/`에 접속한다.
2. 프록시가 OIDC 로그인을 시작한다.
3. OIDC callback 성공 후 Vault에 연결된 n8n 계정이 없으면 `/n8n-link`로 이동한다.
4. 사용자가 n8n 이메일/비밀번호를 입력한다.
5. 프록시는 입력받은 정보로 n8n upstream의 `/rest/login`에 서버 사이드 요청을 보낸다.
6. 성공하면 OIDC subject와 n8n credential을 Vault에 저장한다.
7. 프록시는 n8n이 발급한 세션 쿠키를 브라우저 도메인에 맞게 재작성해서 내려준다.
8. 사용자는 n8n 콘솔로 이동한다.

### 2. 이후 콘솔 로그인

1. 사용자가 `https://proxy.example.com/`에 접속한다.
2. OIDC 세션이 없으면 OIDC 로그인으로 보낸다.
3. OIDC callback 성공 후 Vault에서 n8n credential을 조회한다.
4. 프록시는 서버 사이드에서 n8n `/rest/login`을 호출한다.
5. n8n 세션 쿠키를 브라우저에 내려준다.
6. 원래 요청 경로로 redirect한다.

### 3. webhook/form 요청

1. 외부 서비스가 `https://proxy.example.com/webhook/...` 또는 `https://proxy.example.com/form/...` 형태로 호출한다.
2. 프록시는 OIDC 인증을 요구하지 않는다.
3. 요청 method, path, query, body, headers를 보존해서 n8n upstream으로 전달한다.
4. n8n 응답을 그대로 반환한다.
5. 절대 OIDC redirect HTML을 반환하면 안 된다.

## 기능 요구사항

### OIDC 인증

- Authorization Code Flow with PKCE를 사용한다.
- `state`와 `nonce`를 검증한다.
- OIDC subject key는 `{issuer, subject}` 조합으로 식별한다.
- email claim은 표시/감사용으로만 사용하고 primary key로 쓰지 않는다.
- callback 성공 후 자체 proxy session을 만든다.

### n8n 계정 연결

- `/n8n-link`는 OIDC 인증된 사용자만 접근 가능하다.
- 계정 연결 시 n8n credential을 바로 Vault에 저장하지 말고 먼저 n8n `/rest/login`으로 검증한다.
- 검증 성공 시에만 Vault에 저장한다.
- 같은 OIDC 사용자가 재연결하면 기존 Vault 값을 덮어쓴다.
- 사용자는 `/n8n-link`에서 기존 연결을 삭제할 수 있어야 한다.

### n8n 로그인 브리지

- 외부 클라이언트가 직접 `/rest/login`을 호출하는 것은 허용하지 않는다.
- 프록시 서버가 upstream n8n으로 보내는 server-to-server 요청만 n8n `/rest/login`을 사용할 수 있다.
- 현재 n8n master 기준 login payload는 JSON `{ "emailOrLdapLoginId": "...", "password": "..." }`다.
- 구버전 n8n 호환이 필요하면 `{ "email": "..." }` payload fallback을 별도 compatibility 옵션으로만 제공한다.
- MFA가 켜진 n8n 계정은 자동 로그인을 지원하지 않는다. `/rest/login`이 MFA error를 반환하면 사용자에게 "n8n 계정 MFA를 해제하거나 별도 지원 구현 필요" 상태를 보여준다.

### 프록시 라우팅

- 인증 없이 바이패스할 public execution path를 명시적으로 관리한다.
- 기본 public bypass prefix:
  - `/webhook/`
  - `/webhook-test/`
  - `/webhook-waiting/`
  - `/form/`
  - `/form-test/`
  - `/forms/`
  - `/forms-test/`
- `/rest/login`은 외부 요청에서 차단한다.
- `/rest/logout`은 n8n logout만 수행하고 proxy OIDC session은 유지한다.
- `/signout`은 n8n UI signout landing path로 취급하며 proxy OIDC session은 유지한다.
- `/auth/logout`은 프록시 자체 logout endpoint이며 proxy session과 n8n session을 함께 제거한다.
- `/auth/*`, `/n8n-link`는 프록시 자체 endpoint다.
- 그 외 모든 요청은 OIDC 인증 및 n8n 세션 보장 후 upstream으로 전달한다.

### 쿠키 처리

- n8n upstream이 내려준 `Set-Cookie`를 proxy public host 기준으로 재작성한다.
- `Domain`은 제거하거나 proxy host로 맞춘다. 기본은 Domain 제거(host-only cookie)다.
- `Path`는 `/`로 유지한다.
- HTTPS 환경에서는 `Secure`를 강제한다.
- `HttpOnly`는 유지한다.
- `SameSite`는 기본 `Lax`로 설정한다. 외부 iframe/embed 요구가 생기기 전까지 `None`을 쓰지 않는다.
- 프록시 자체 세션 쿠키 이름은 `__Host-n8np_session`을 사용한다.

### 직접 로그인 제한

- 외부 사용자는 n8n 네이티브 로그인 화면을 사용하지 않는다.
- `/signin`, `/login`, `/rest/login` 접근은 프록시 OIDC 플로우로 전환하거나 차단한다.
- 운영자가 n8n 네이티브 로그인으로 접속해야 하는 경우 별도 admin-only console 경로 또는 내부 네트워크에서 upstream n8n에 직접 접속한다.
- 이 admin-only 접근은 이 프록시의 public listener에 포함하지 않는다.

## 비기능 요구사항

- 모든 credential은 Vault에만 저장한다.
- 애플리케이션 로그에 비밀번호, n8n session cookie, OIDC token, authorization code를 남기지 않는다.
- webhook/form 요청은 긴 응답 시간을 가질 수 있으므로 console UI timeout과 분리한다.
- WebSocket/SSE/streaming 응답을 reverse proxy가 끊지 않아야 한다.
- health check는 OIDC/Vault/n8n 상태를 분리해서 제공한다.
- 모든 보안 관련 실패는 사용자에게 상세 내부 정보를 노출하지 않고, 서버 로그에는 correlation id로 남긴다.
