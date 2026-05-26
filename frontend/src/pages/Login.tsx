import { useState, type FormEvent } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { login } from "@/api/settings";
import { useAuth } from "@/hooks/useAuth";
import type { UserRole } from "@/hooks/useAuth";

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const setAuth = useAuth((s) => s.setAuth);
  const from = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname ?? "/";

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const { access_token, refresh_token } = await login(username, password);
      // Decode role from JWT payload (base64)
      const payload = JSON.parse(atob(access_token.split(".")[1])) as {
        role: UserRole;
        sub: string;
      };
      setAuth(access_token, refresh_token, payload.role, payload.sub);
      navigate(from, { replace: true });
    } catch {
      setError("Invalid credentials. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="w-full max-w-sm bg-card border border-border rounded-lg p-8">
        <h1 className="text-lg font-bold text-foreground mb-1">Sailor</h1>
        <p className="text-xs text-muted-foreground mb-6">
          Automated vulnerability discovery pipeline
        </p>

        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-secondary border border-border rounded text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              autoComplete="username"
              required
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-secondary border border-border rounded text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <p className="text-xs text-red-400">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors disabled:opacity-50"
          >
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>
        <p className="mt-4 text-xs text-center text-muted-foreground">
          No account?{" "}
          <Link to="/register" className="text-primary hover:underline">Create one →</Link>
        </p>
      </div>
    </div>
  );
}
