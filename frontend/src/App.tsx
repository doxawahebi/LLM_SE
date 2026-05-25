import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NuqsAdapter } from "nuqs/adapters/react-router/v6";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { AppShell }      from "./components/AppShell";
import { RequireAuth }   from "./components/RequireAuth";
import { Login }         from "./pages/Login";
import { Register }      from "./pages/Register";
import { Dashboard }     from "./pages/Dashboard";
import { NewRun }        from "./pages/NewRun";
import { RunDetail }     from "./pages/RunDetail";
import { SpecDetail }    from "./pages/SpecDetail";
import { WorkerView }    from "./pages/WorkerView";
import { LogsView }      from "./pages/LogsView";
import { Settings }      from "./pages/Settings";
import { UserManagement } from "./pages/UserManagement";

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
    },
  },
});

export default function App() {
  return (
    <ErrorBoundary>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <NuqsAdapter>
          <Routes>

            {/* ── Public routes ──────────────────────────────── */}
            <Route path="/login"    element={<Login />} />
            <Route path="/register" element={<Register />} />

            {/* ── Protected routes (inside AppShell) ─────────── */}
            <Route element={<RequireAuth />}>
              <Route element={<AppShell />}>
                <Route path="/"                            element={<Dashboard />} />
                <Route path="/runs/new"                    element={<NewRun />} />
                <Route path="/runs/:run_id"                element={<RunDetail />} />
                <Route path="/runs/:run_id/specs/:spec_id" element={<SpecDetail />} />
                <Route path="/runs/:run_id/workers"        element={<WorkerView />} />
                <Route path="/runs/:run_id/logs"           element={<LogsView />} />
                <Route path="/settings"                    element={<Settings />} />
                <Route path="/settings/users"              element={<UserManagement />} />
              </Route>
            </Route>

            {/* ── Catch-all ─────────────────────────────────── */}
            <Route path="*" element={<Navigate to="/" replace />} />

          </Routes>
        </NuqsAdapter>
      </BrowserRouter>
    </QueryClientProvider>
    </ErrorBoundary>
  );
}
