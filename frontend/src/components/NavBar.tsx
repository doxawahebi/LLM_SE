import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { logout } from "@/api/settings";

export function NavBar() {
  const { username, role, clearAuth } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    try { await logout(); } catch { /* ignore */ }
    clearAuth();
    navigate("/login");
  }

  return (
    <nav className="border-b border-border bg-card px-6 py-2 flex items-center gap-6">
      <Link to="/" className="text-sm font-bold text-foreground hover:text-primary transition-colors">
        Sailor
      </Link>
      <div className="flex-1" />
      <span className="text-xs text-muted-foreground">
        {username} · {role}
      </span>
      <Link to="/settings" className="text-xs text-muted-foreground hover:text-foreground transition-colors">
        Settings
      </Link>
      {role === "admin" && (
        <Link to="/settings/users" className="text-xs text-muted-foreground hover:text-foreground transition-colors">
          Users
        </Link>
      )}
      <button
        onClick={() => void handleLogout()}
        className="text-xs text-muted-foreground hover:text-foreground transition-colors"
      >
        Logout
      </button>
    </nav>
  );
}
