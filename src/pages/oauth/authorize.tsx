import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'chen-the-dawnstreak';
import { Alert, Button, Card, Spinner } from '@heroui/react';
import { apiFetch, ApiError } from '../../lib/api';
import { loadSession } from '../../lib/auth';

/**
 * OAuth 2.0 authorize entry point for relying parties.
 *
 * The relying party sends the browser here with the standard
 * `?response_type=code&client_id=...&redirect_uri=...&state=...&scope=...`
 * query. We inspect the current session; if there is none, we bounce to
 * /login?return=<this full URL>. Otherwise we show a consent screen and
 * POST to /api/oauth/authorize on click, then follow the `redirect_url`
 * the server returns (which already carries `?code=...&state=...`).
 */
export default function OAuthAuthorize() {
  const [params] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const clientId = params.get('client_id') ?? '';
  const redirectUri = params.get('redirect_uri') ?? '';
  const responseType = params.get('response_type') ?? 'code';
  const state = params.get('state') ?? '';
  const scope = params.get('scope') ?? '';

  useEffect(() => {
    if (loadSession()) return;
    // Not logged in yet — bounce to /login so the user can come back here.
    const here = window.location.pathname + window.location.search;
    const loginUrl = new URL('/login', window.location.origin);
    loginUrl.searchParams.set('return', here);
    window.location.replace(loginUrl.toString());
  }, []);

  const missing = !clientId || !redirectUri;
  const wrongType = responseType !== 'code';

  async function handleAuthorize() {
    setError(null);
    setBusy(true);
    try {
      const res = await apiFetch<{ redirect_url: string }>(
        '/api/oauth/authorize',
        {
          method: 'POST',
          body: JSON.stringify({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: responseType,
            state: state || null,
            scope: scope || null,
          }),
        },
      );
      window.location.href = res.redirect_url;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '授权失败，请稍后重试');
      setBusy(false);
    }
  }

  function handleDeny() {
    if (!redirectUri) {
      window.location.href = '/';
      return;
    }
    // Mirror the OAuth 2.0 error response: send the user back to the
    // relying party with `error=access_denied`. The RP decides how to
    // surface that to the user — we don't render our own deny screen here.
    try {
      const u = new URL(redirectUri);
      u.searchParams.set('error', 'access_denied');
      if (state) u.searchParams.set('state', state);
      window.location.href = u.toString();
    } catch {
      window.location.href = '/';
    }
  }

  const session = loadSession();
  if (!session) {
    return (
      <Card className="w-full">
        <Card.Content className="flex items-center justify-center gap-3 py-6">
          <Spinner />
          <span style={{ color: 'var(--muted)' }}>正在跳转到登录页…</span>
        </Card.Content>
      </Card>
    );
  }

  if (missing || wrongType) {
    return (
      <Card className="w-full">
        <Card.Header>
          <Card.Title>授权请求无效</Card.Title>
        </Card.Header>
        <Card.Content>
          <Alert status="danger">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>
                {wrongType
                  ? `不支持的 response_type: ${responseType}`
                  : '缺少 client_id 或 redirect_uri'}
              </Alert.Title>
            </Alert.Content>
          </Alert>
        </Card.Content>
        <Card.Footer className="mt-4">
          <Link to="/">
            <Button fullWidth variant="tertiary">
              返回首页
            </Button>
          </Link>
        </Card.Footer>
      </Card>
    );
  }

  return (
    <Card className="w-full">
      <Card.Header>
        <Card.Title>授权确认</Card.Title>
        <Card.Description>
          <strong>{clientId}</strong> 希望使用你的紫霄实验室云账号登录。
        </Card.Description>
      </Card.Header>
      <Card.Content className="flex flex-col gap-4">
        {error ? (
          <Alert status="danger">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{error}</Alert.Title>
            </Alert.Content>
          </Alert>
        ) : null}
        <div
          className="text-sm"
          style={{ color: 'var(--muted)', lineHeight: 1.6 }}
        >
          当前账号：<strong>{session.user.username}</strong>
          <br />
          授权后，应用将获取你的：用户名、邮箱、显示名、头像及简介。
          <br />
          跳转目标：<code>{redirectUri}</code>
        </div>
      </Card.Content>
      <Card.Footer className="mt-4 flex flex-col gap-3">
        <Button type="button" fullWidth isPending={busy} onPress={handleAuthorize}>
          {busy ? '正在授权…' : '允许'}
        </Button>
        <Button
          type="button"
          fullWidth
          variant="tertiary"
          isDisabled={busy}
          onPress={handleDeny}
        >
          拒绝
        </Button>
      </Card.Footer>
    </Card>
  );
}
