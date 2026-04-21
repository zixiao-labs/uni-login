import { useState, type FormEvent } from 'react';
import { Link } from 'chen-the-dawnstreak';
import {
  Alert,
  Button,
  Card,
  Description,
  FieldError,
  Form,
  Input,
  Label,
  TextField,
} from '@heroui/react';
import { apiFetch, ApiError } from '../lib/api';
import { setSession } from '../lib/session-store';
import type { AuthResponse, RegisterRequest } from '../lib/types';

const CONSOLE_URL = import.meta.env.VITE_MAIN_CONSOLE_URL || 'http://localhost:5174/';

/**
 * Render a registration page with fields for username, email, optional display name, and password.
 *
 * Handles client-side validation, sends a registration request to the server, sets the session on success,
 * redirects the browser to the console URL, and shows form-level error messages and a loading state while submitting.
 *
 * @returns The React element for the registration UI.
 */
export default function Register() {
  const [formError, setFormError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError(null);
    const fd = new FormData(e.currentTarget);
    const username = String(fd.get('username') ?? '').trim();
    const email = String(fd.get('email') ?? '').trim();
    const password = String(fd.get('password') ?? '');
    const display_name = String(fd.get('display_name') ?? '').trim();

    if (!username || !email || !password) {
      setFormError('请填写必填字段');
      return;
    }
    if (password.length < 8) {
      setFormError('密码长度至少 8 位');
      return;
    }

    const payload: RegisterRequest = { username, email, password, display_name };
    setLoading(true);
    try {
      const res = await apiFetch<AuthResponse>('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setSession(res.token, res.user);
      window.location.href = CONSOLE_URL;
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : '注册失败，请稍后重试';
      setFormError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="w-full">
      <Card.Header>
        <Card.Title>注册</Card.Title>
        <Card.Description>创建紫霄实验室云账号</Card.Description>
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
          <TextField name="username" isRequired autoComplete="username">
            <Label>用户名</Label>
            <Input placeholder="admin" />
            <Description>仅限字母、数字和下划线；登录时使用</Description>
            <FieldError />
          </TextField>
          <TextField name="email" type="email" isRequired autoComplete="email">
            <Label>邮箱</Label>
            <Input placeholder="you@example.com" />
            <FieldError />
          </TextField>
          <TextField name="display_name" autoComplete="name">
            <Label>显示名（可选）</Label>
            <Input placeholder="你在界面里展示的名字" />
            <FieldError />
          </TextField>
          <TextField name="password" type="password" isRequired autoComplete="new-password">
            <Label>密码</Label>
            <Input placeholder="至少 8 位" />
            <FieldError />
          </TextField>
        </Card.Content>
        <Card.Footer className="mt-4 flex flex-col gap-3">
          <Button type="submit" fullWidth isPending={loading}>
            {loading ? '创建中…' : '创建账号'}
          </Button>
          <div className="text-center text-sm" style={{ color: 'var(--muted)' }}>
            已有账号？<Link to="/login">前往登录</Link>
          </div>
        </Card.Footer>
      </Form>
    </Card>
  );
}
