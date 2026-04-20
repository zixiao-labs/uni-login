import { Outlet } from 'chen-the-dawnstreak';

export default function Layout() {
  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4 py-10"
      style={{ background: 'var(--background)' }}
    >
      <header className="mb-8 flex flex-col items-center gap-2">
        <div
          className="w-12 h-12 rounded-2xl flex items-center justify-center text-2xl font-bold"
          style={{ background: 'var(--accent)', color: 'var(--accent-foreground)' }}
        >
          紫
        </div>
        <h1 className="text-lg font-semibold" style={{ color: 'var(--foreground)' }}>
          紫霄实验室云账号
        </h1>
        <p className="text-xs" style={{ color: 'var(--muted)' }}>
          Zixiao Labs Cloud Account
        </p>
      </header>
      <main className="w-full max-w-md">
        <Outlet />
      </main>
      <footer className="mt-8 text-xs" style={{ color: 'var(--muted)' }}>
        © {new Date().getFullYear()} zixiao-labs · 玉虚宫 DevOps
      </footer>
    </div>
  );
}
