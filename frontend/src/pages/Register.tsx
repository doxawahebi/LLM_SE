import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import zxcvbn from "zxcvbn";
import { register } from "@/api/client";

const STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Good", "Strong"] as const;
const STRENGTH_COLORS = [
  "bg-red-500",
  "bg-orange-500",
  "bg-yellow-500",
  "bg-green-500",
  "bg-emerald-500",
] as const;

export function Register() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    confirm: "",
    display_name: "",
  });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [isFirstUser, setIsFirstUser] = useState(false);

  const strength = form.password ? zxcvbn(form.password) : null;
  const strengthScore = strength?.score ?? 0;
  const canSubmit =
    form.username.length >= 3 &&
    form.email.includes("@") &&
    form.password.length >= 12 &&
    form.password === form.confirm &&
    strengthScore >= 3;

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await register({
        username: form.username,
        email: form.email,
        password: form.password,
        display_name: form.display_name || undefined,
      });
      if (result.role === "admin") {
        setIsFirstUser(true);
        setTimeout(() => navigate("/login"), 3000);
      } else {
        navigate("/login", { state: { toast: "Account created. Please sign in." } });
      }
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string; message?: string } } })
        ?.response?.data?.detail ?? "Registration failed";
      setError(String(msg));
    } finally {
      setLoading(false);
    }
  }

  if (isFirstUser) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="bg-card border border-border rounded-xl p-8 w-full max-w-md text-center space-y-3">
          <div className="text-2xl">🎉</div>
          <h1 className="text-lg font-bold text-foreground">
            You are the first user — admin role granted
          </h1>
          <p className="text-sm text-muted-foreground">
            Redirecting to login…
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="bg-card border border-border rounded-xl p-8 w-full max-w-md space-y-6">
        <h1 className="text-xl font-bold text-foreground">Create a Sailor account</h1>

        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <Field label="Username">
            <input
              type="text"
              autoComplete="username"
              required
              minLength={3}
              maxLength={32}
              pattern="[a-zA-Z0-9_]+"
              value={form.username}
              onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
              className={inputCls}
              placeholder="alice"
            />
          </Field>

          <Field label="Email">
            <input
              type="email"
              autoComplete="email"
              required
              value={form.email}
              onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
              className={inputCls}
              placeholder="alice@example.com"
            />
          </Field>

          <Field label="Password">
            <input
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={form.password}
              onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
              className={inputCls}
            />
            {form.password && (
              <div className="mt-1 space-y-1">
                <div className="flex gap-0.5">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div
                      key={i}
                      className={`h-1.5 flex-1 rounded-full transition-all ${
                        i <= strengthScore
                          ? STRENGTH_COLORS[strengthScore]
                          : "bg-muted"
                      }`}
                    />
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">
                  {STRENGTH_LABELS[strengthScore]}
                  {strengthScore < 3 && " — must reach Good"}
                </p>
              </div>
            )}
          </Field>

          <Field label="Confirm">
            <input
              type="password"
              autoComplete="new-password"
              required
              value={form.confirm}
              onChange={(e) => setForm((f) => ({ ...f, confirm: e.target.value }))}
              className={inputCls}
            />
            {form.confirm && form.password !== form.confirm && (
              <p className="text-xs text-red-400 mt-1">Passwords do not match</p>
            )}
          </Field>

          <Field label="Display name">
            <input
              type="text"
              value={form.display_name}
              onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))}
              className={inputCls}
              placeholder="Optional"
            />
          </Field>

          {error && (
            <p className="text-sm text-red-400">{error}</p>
          )}

          <button
            type="submit"
            disabled={!canSubmit || loading}
            className="w-full py-2.5 text-sm font-medium bg-primary text-primary-foreground rounded hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            {loading ? "Creating account…" : "Create account"}
          </button>
        </form>

        <p className="text-sm text-center text-muted-foreground">
          Already have an account?{" "}
          <Link to="/login" className="text-primary hover:underline">Sign in →</Link>
        </p>
      </div>
    </div>
  );
}

const inputCls =
  "w-full px-3 py-2 text-sm bg-muted border border-border rounded text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <label className="text-xs text-muted-foreground">{label}</label>
      {children}
    </div>
  );
}
