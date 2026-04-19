import { createSimpleStore } from 'chen-the-dawnstreak';
import { loadSession, saveSession, clearSession, type Session } from './auth';
import type { UserProfile } from './types';

interface SessionState {
  session: Session | null;
}

const store = createSimpleStore<SessionState>({ session: loadSession() });

export const useSession = store.useStore;

export function setSession(token: string, user: UserProfile): void {
  saveSession(token, user);
  store.setState({ session: { token, user } });
}

export function logout(): void {
  clearSession();
  store.setState({ session: null });
}
