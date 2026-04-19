import type { UserProfile } from './types';

const TOKEN_KEY = 'yuxu_token';
const USER_KEY = 'yuxu_user';

export interface Session {
  token: string;
  user: UserProfile;
}

export function saveSession(token: string, user: UserProfile): void {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function loadSession(): Session | null {
  const token = localStorage.getItem(TOKEN_KEY);
  const userRaw = localStorage.getItem(USER_KEY);
  if (!token || !userRaw) return null;
  try {
    return { token, user: JSON.parse(userRaw) as UserProfile };
  } catch {
    return null;
  }
}

export function clearSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}
