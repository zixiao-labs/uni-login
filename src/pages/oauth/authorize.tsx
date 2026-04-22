import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'chen-the-dawnstreak';
import { Alert, Button, Card, Spinner } from '@heroui/react';
import { apiFetch, ApiError } from '../../lib/api';
import { loadSession } from '../../lib/auth';

/**
 * Render the OAuth 2.0 authorization page shown to a user when a relying party requests authorization.
 *
 * If the user is not authenticated, redirects the browser to the login page with a return URL back to this authorize endpoint.
 * When authenticated and the request is valid, shows a consent UI that either:
 * - Initiates authorization by POSTing the OAuth parameters to /api/oauth/authorize and then navigates to the server-provided redirect URL on success, or
 * - Returns the OAuth error response to the relying party by navigating to `redirect_uri?error=access_denied` (including `state` when present) when the user denies.
 *
 * @returns The React element rendering the authorization UI or interim redirect state.
 */
export default function OAuthAuthorize() {
  const [params] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const clientId = params.get('client_id') ?? '';
  const redirectUri = params.get('redirect_uri') ?? '';
  const responseType = params.get('response_type');
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

  const missing = !clientId || !redirectUri || !responseType;
  const wrongType = responseType !== 'code';

  /**
   * Initiates the OAuth authorization request and navigates the browser to the redirect URL returned by the server on success.
   *
   * Sets local busy state while the request is in flight. On failure, sets the local error state to the server error message when available, or to "授权失败，请稍后重试", and clears the busy state.
   */
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

  /**
   * Navigates the browser to return an OAuth 2.0 error response to the relying party.
   *
   * Validates the client_id/redirect_uri pair with the server before redirecting to
   * prevent open-redirect abuse. If validation succeeds, navigates to `redirectUri`
   * with `error=access_denied` (and `state` when present). On validation failure or
   * missing redirectUri, navigates to `/`.
   */
  async function handleDeny() {
    if (!redirectUri || !clientId) {
      window.location.href = '/';
      return;
    }

    setBusy(true);
    try {
      // Validate the client_id/redirect_uri pair with the server to ensure
      // it's an allowed redirect target before performing the client-side redirect.
      // We use the validate endpoint which only verifies parameters without
      // minting an AuthCode. This allows us to safely construct error redirects.
      const res = await apiFetch<{ redirect_url: string }>('/api/oauth/authorize/validate', {
        method: 'POST',
        body: JSON.stringify({
          client_id: clientId,
          redirect_uri: redirectUri,
          response_type: responseType,
          state: state || null,
          scope: scope || null,
        }),
      });

      // Server validated the redirect_uri, safe to redirect with error
      const u = new URL(res.redirect_url);
      u.searchParams.set('error', 'access_denied');
      window.location.href = u.toString();
    } catch {
      // Validation failed or other error — don't redirect to potentially malicious URL
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