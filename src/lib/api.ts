import type { ApiErrorBody } from './types';
import { loadSession } from './auth';

/**
 * Base URL for API calls. In dev, point at the backend (e.g. http://localhost:8080);
 * leave empty in prod so same-origin paths are used.
 */
const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');

export class ApiError extends Error {
  readonly kind: string;
  readonly status: number;

  constructor(status: number, body: Partial<ApiErrorBody>, fallback: string) {
    super(body.message || fallback);
    this.status = status;
    this.kind = body.error || 'unknown';
  }
}

export function authHeader(): Record<string, string> {
  const session = loadSession();
  return session ? { Authorization: `Bearer ${session.token}` } : {};
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const url = path.startsWith('http') ? path : `${API_BASE}${path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...authHeader(),
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  const res = await fetch(url, { ...init, headers });
  if (res.status === 204) return undefined as T;

  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    // keep body null
  }
  if (!res.ok) {
    throw new ApiError(
      res.status,
      (body as Partial<ApiErrorBody>) ?? {},
      `HTTP ${res.status}`,
    );
  }
  return body as T;
}
