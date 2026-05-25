import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { logout } from '../api/settings'
import { ErrorToastContainer } from './ErrorToast'

export function AppShell() {
  const { username, role, clearAuth } = useAuth()
  const navigate = useNavigate()

  async function handleLogout() {
    try { await logout() } catch { /* ignore */ }
    clearAuth()
    navigate('/login')
  }

  return (
    <div className="flex h-screen bg-background text-foreground">

      {/* ── Sidebar navigation ─────────────────────────────── */}
      <aside className="w-56 flex-shrink-0 bg-card border-r border-border flex flex-col">

        <div className="px-4 py-5 border-b border-border">
          <span className="text-base font-bold text-foreground tracking-tight">
            ⚓ Sailor
          </span>
        </div>

        <nav className="flex-1 px-2 py-4 space-y-1">
          <NavItem to="/"         label="Runs"      icon="▦" />
          <NavItem to="/runs/new" label="Run Pipeline" icon="▶" />
          <NavItem to="/settings" label="Settings"  icon="⚙" />
          {role === 'admin' && (
            <NavItem to="/settings/users" label="Users" icon="👥" />
          )}
        </nav>

        <div className="px-4 py-4 border-t border-border">
          <p className="text-xs text-muted-foreground truncate mb-2">
            {username ?? 'unknown'}
            <span className="ml-2 text-[10px] uppercase opacity-60">{role}</span>
          </p>
          <button
            onClick={() => void handleLogout()}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Sign out
          </button>
        </div>
      </aside>

      {/* ── Main content area ──────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>

      <ErrorToastContainer />
    </div>
  )
}

function NavItem({ to, label, icon }: { to: string; label: string; icon: string }) {
  return (
    <NavLink
      to={to}
      end={to === '/'}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
          isActive
            ? 'bg-primary text-primary-foreground'
            : 'text-muted-foreground hover:bg-secondary hover:text-foreground'
        }`
      }
    >
      <span className="text-base leading-none">{icon}</span>
      {label}
    </NavLink>
  )
}
