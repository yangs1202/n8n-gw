# n8n OIDC Proxy 구현 문서

이 디렉터리는 빈 저장소에서 바로 구현을 시작할 수 있도록 작성한 개발 사양이다. 코딩 에이전트는 아래 문서를 순서대로 읽고, 문서의 MUST/SHOULD 규칙을 그대로 구현한다.

## 문서 순서

1. [요구사항](./requirements.md)
2. [아키텍처](./architecture.md)
3. [구현 사양](./implementation-spec.md)
4. [보안 및 운영](./security-and-ops.md)
5. [테스트 계획](./test-plan.md)

## 핵심 결정

- 이 서비스는 n8n 앞단에 위치하는 reverse proxy다.
- n8n Free/Community 버전 자체를 수정하지 않는다.
- 사람 사용자의 웹 콘솔 접근은 OIDC로만 인증한다.
- n8n 네이티브 이메일/비밀번호 직접 로그인은 외부에 노출하지 않는다.
- 프록시는 OIDC 사용자와 n8n 계정 정보를 Vault에 매핑하고, 서버 사이드에서만 n8n `/rest/login`을 호출한다.
- webhook/form 같은 외부 실행 엔드포인트는 OIDC 인증 없이 n8n으로 바이패스한다.
- 나머지 n8n UI/API 요청은 인증된 세션과 n8n 세션 쿠키가 있을 때만 통과시킨다.

## 권장 기술 스택

- Language: Go 1.23+
- HTTP: `net/http`, `net/http/httputil.ReverseProxy`
- OIDC: `github.com/coreos/go-oidc/v3/oidc`, `golang.org/x/oauth2`
- Vault: `github.com/hashicorp/vault/api`
- Session store: Redis
- Config: environment variables
- Runtime: container image

Go를 권장하는 이유는 쿠키 재작성, streaming reverse proxy, timeout 제어, single binary 배포가 단순하기 때문이다. 다른 언어를 선택해도 되지만, 이 문서의 HTTP 계약과 보안 정책은 바꾸면 안 된다.

## 외부 참고

- n8n public API는 공식 API key 기반이며, 이 프로젝트가 사용하는 `/rest/login`은 n8n UI 내부 로그인 엔드포인트다. 공식 API와 혼동하지 않는다: https://docs.n8n.io/api/
- 현재 n8n source의 `AuthController`는 `POST /rest/login`에서 `emailOrLdapLoginId`, `password`, `mfaCode`, `mfaRecoveryCode` payload를 사용하고 로그인 쿠키를 발급한다: https://raw.githubusercontent.com/n8n-io/n8n/master/packages/cli/src/controllers/auth.controller.ts
- n8n Webhook node는 test URL과 production URL을 구분한다: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/
- n8n Form Trigger도 test/production URL을 구분한다: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.formtrigger/
- reverse proxy 뒤의 n8n webhook URL은 `WEBHOOK_URL` 등 public URL 설정이 필요하다: https://docs.n8n.io/hosting/configuration/configuration-examples/webhook-url/
