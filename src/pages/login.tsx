import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'chen-the-dawnstreak';
import {
  Alert,
  Button,
  Card,
  FieldError,
  Form,
  Input,
  Label,
  TextField,
} from '@heroui/react';
import { apiFetch, ApiError } from '../lib/api';
import { setSession } from '../lib/session-store';
import type { AuthResponse, LoginRequest } from '../lib/types';

const CONSOLE_URL = import.meta.env.VITE_MAIN_CONSOLE_URL || 'http://localhost:5174/';
const GITHUB_CLIENT_ID = import.meta.env.VITE_GITHUB_CLIENT_ID;

function beginGithubOauth() {
  if (!GITHUB_CLIENT_ID) {
    alert('未配置 VITE_GITHUB_CLIENT_ID，GitHub 登录不可用');
    return;
  }
  const state = crypto.randomUUID();
  sessionStorage.setItem('github_oauth_state', state);
  const redirectUri = `${window.location.origin}/oauth/callback`;
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    scope: 'read:user user:email',
    redirect_uri: redirectUri,
    state,
  });
  window.location.href = `https://github.com/login/oauth/authorize?${params.toString()}`;
}

export default function Login() {
  const [params] = useSearchParams();
  const returnTo = params.get('return') || CONSOLE_URL;

  const [formError, setFormError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    const fd = new FormData(e.currentTarget);
    const payload: LoginRequest = {
      username_or_email: String(fd.get('username_or_email') ?? '').trim(),
      password: String(fd.get('password') ?? ''),
    };
    if (!payload.username_or_email || !payload.password) {
      setFormError('请填写用户名和密码');
      return;
    }
    setLoading(true);
    try {
      const res = await apiFetch<AuthResponse>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setSession(res.token, res.user);
      window.location.href = returnTo;
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : '登录失败，请稍后重试';
      setFormError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="w-full">
      <Card.Header>
        <Card.Title>登录</Card.Title>
        <Card.Description>
          使用紫霄实验室云账号登录，统一访问玉虚宫 DevOps 及其他接入的服务
        </Card.Description>
      </Card.Header>
      <Form onSubmit={handleSubmit}>
        <Card.Content className="flex flex-col gap-4">
          {formError ? (
            <Alert status="danger">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{formError}</Alert.Title>
              </Alert.Content>
            </Alert>
          ) : null}
          <TextField name="username_or_email" isRequired autoComplete="username">
            <Label>用户名或邮箱</Label>
            <Input placeholder="admin 或 admin@example.com" />
            <FieldError />
          </TextField>
          <TextField name="password" type="password" isRequired autoComplete="current-password">
            <Label>密码</Label>
            <Input placeholder="••••••••" />
            <FieldError />
          </TextField>
        </Card.Content>
        <Card.Footer className="mt-4 flex flex-col gap-3">
          <Button type="submit" fullWidth isPending={loading}>
            {loading ? '登录中…' : '登录'}
          </Button>
          <Button type="button" fullWidth variant="tertiary" onPress={beginGithubOauth}>
            使用 GitHub 登录
          </Button>
          <div className="text-center text-sm" style={{ color: 'var(--muted)' }}>
            还没有账号？<Link to="/register">立即注册</Link>
          </div>
        </Card.Footer>
      </Form>
    </Card>
  );
}
