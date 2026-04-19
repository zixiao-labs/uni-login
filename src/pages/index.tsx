import { useEffect } from 'react';
import { useNavigate } from 'chen-the-dawnstreak';
import { Spinner } from '@heroui/react';
import { loadSession } from '../lib/auth';

const CONSOLE_URL = import.meta.env.VITE_MAIN_CONSOLE_URL || 'http://localhost:5174/';

export default function Index() {
  const navigate = useNavigate();

  useEffect(() => {
    const session = loadSession();
    if (session) {
      window.location.href = CONSOLE_URL;
    } else {
      navigate('/login', { replace: true });
    }
  }, [navigate]);

  return (
    <div className="flex items-center justify-center py-10">
      <Spinner />
    </div>
  );
}
