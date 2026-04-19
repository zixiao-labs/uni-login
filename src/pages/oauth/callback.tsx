import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'chen-the-dawnstreak';
import { Alert, Button, Card, Spinner } from '@heroui/react';
import { apiFetch, ApiError } from '../../lib/api';
import { setSession } from '../../lib/session-store';
import type { AuthResponse, GithubOauthRequest } from '../../lib/types';

const CONSOLE_URL = import.meta.env.VITE_MAIN_CONSOLE_URL || 'http://localhost:5174/';

export default function OauthCallback() {
  const [params] = useSearchParams();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = params.get('code');
    const returnedState = params.get('state');
    const savedState = sessionStorage.getItem('github_oauth_state');
    sessionStorage.removeItem('github_oauth_state');

    const providerError = params.get('error_description') || params.get('error');
    if (providerError) {
      setError(`GitHub 返回错误：${providerError}`);
      return;
    }
    if (!code || !returnedState) {
      setError('缺少 code 或 state 参数');
      return;
    }
    if (!savedState || savedState !== returnedState) {
      setError('state 校验失败，请重新发起登录');
      return;
    }

    const payload: GithubOauthRequest = { code, state: returnedState };
    apiFetch<AuthResponse>('/api/auth/github/callback', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
      .then((res) => {
        setSession(res.token, res.user);
        window.location.href = CONSOLE_URL;
      })
      .catch((err) => {
        setError(err instanceof ApiError ? err.message : 'GitHub 登录失败，请稍后重试');
      });
  }, [params]);

  if (error) {
    return (
      <Card className="w-full">
        <Card.Header>
          <Card.Title>GitHub 登录失败</Card.Title>
        </Card.Header>
        <Card.Content className="flex flex-col gap-3">
          <Alert status="danger">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{error}</Alert.Title>
            </Alert.Content>
          </Alert>
        </Card.Content>
        <Card.Footer className="mt-4">
          <Link to="/login">
            <Button fullWidth variant="tertiary">
              返回登录
            </Button>
          </Link>
        </Card.Footer>
      </Card>
    );
  }

  return (
    <Card className="w-full">
      <Card.Content className="flex flex-col items-center gap-4 py-8">
        <Spinner />
        <p style={{ color: 'var(--muted)' }}>正在完成 GitHub 登录…</p>
      </Card.Content>
    </Card>
  );
}
