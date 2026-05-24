# CLAUDE_fix_frontend_issues.md
# Fix: Frontend broken — /runs/new does nothing, no live progress
#
# Trigger: "Read CLAUDE.md, then execute design/CLAUDE_fix_frontend_issues.md"
#
# This prompt diagnoses all frontend issues systematically,
# fixes them in a guaranteed order, and adds error detection
# so future regressions are caught immediately.

---

## Known Symptoms

```
1. POST /api/runs from /runs/new does nothing (no navigation, no feedback)
2. Run detail page shows no live progress even while pipeline is running
3. General frontend issues throughout (unspecified)
```

---

## Step 0. Read Context

```
Read in this order (stop if a file is missing — report which one):
  1. CLAUDE.md
  2. spec/frontend_spec.md
  3. spec/backend_spec.md        §3.1 Run state machine
  4. design/CLAUDE_frontend.md   Component architecture, TypeScript interfaces
  5. design/CLAUDE_infra.md      docker-compose services, ports
```

---

## Step 1. Systematic Diagnosis

Before changing any file, run ALL of these checks and produce a
**Diagnosis Report**. Do not fix anything yet.

### 1A. Backend reachability

```bash
# From inside the frontend container or host:
curl -s http://localhost:8000/api/health
curl -s http://localhost:3000/api/health   # via nginx proxy

# Expected: {"status": "ok"} on both
# If 000 (connection refused): backend is not running
# If 502: nginx proxy config wrong
# If 404: /api/health not implemented
```

### 1B. CORS check

```bash
curl -s -I -X OPTIONS http://localhost:8000/api/runs \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST"

# Expected: Access-Control-Allow-Origin: http://localhost:3000
# If missing: FastAPI CORS middleware not configured
```

### 1C. Auth token flow

```bash
# Attempt login
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<test_user>","password":"<test_pass>"}'

# Expected: {"access_token": "...", "token_type": "bearer", "user": {...}}
# Save access_token as TOKEN for subsequent checks
```

### 1D. Run creation endpoint

```bash
# Create a minimal run (no zip, just JSON to test the endpoint)
curl -s -X POST http://localhost:8000/api/runs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","build_command":"make"}'

# If 422 Unprocessable Entity: request schema mismatch
# If 401: token not accepted
# If 500: backend crash — check docker compose logs backend
```

### 1E. Read frontend source files

Read these files and report what each one currently does:

```
frontend/src/App.tsx              → route definitions
frontend/src/pages/NewRun.tsx     → form submit handler
frontend/src/pages/RunDetail.tsx  → how it fetches/subscribes
frontend/src/api/client.ts        → axios config, base URL, headers
frontend/src/api/runs.ts          → createRun() function
frontend/src/hooks/useSSE.ts      → SSE subscription
frontend/src/hooks/useAuth.ts     → token storage and access
frontend/src/main.tsx             → entry point
frontend/src/index.css            → root height
```

For each file, check:
- Does it exist?
- Does it compile (no obvious TypeScript errors)?
- Does the logic make sense for its purpose?

### 1F. Browser console errors

```bash
# Check frontend container logs for build errors
docker compose logs frontend --tail=50

# Check backend container logs for runtime errors
docker compose logs backend --tail=50

# Check worker logs
docker compose logs worker --tail=30
```

### 1G. SSE endpoint check

```bash
curl -s -N \
  "http://localhost:8000/api/events?topics=runs.all&token=$TOKEN" \
  --max-time 5

# Expected: data: {...} lines arriving every few seconds
# If 401: token param not accepted
# If empty: SSE not publishing events
# If connection refused: /api/events not implemented
```

### 1H. Produce Diagnosis Report

Output a table:

```
Issue                          Status      Root Cause
─────────────────────────────────────────────────────
Backend reachable              PASS/FAIL   <detail>
CORS configured                PASS/FAIL   <detail>
Auth login works               PASS/FAIL   <detail>
POST /api/runs works           PASS/FAIL   <detail>
NewRun.tsx submit handler      PASS/FAIL   <detail>
RunDetail.tsx SSE subscription PASS/FAIL   <detail>
api/client.ts base URL         PASS/FAIL   <detail>
useAuth token passed to API    PASS/FAIL   <detail>
SSE endpoint reachable         PASS/FAIL   <detail>
Frontend CSS root height       PASS/FAIL   <detail>
```

Proceed to Step 2 only after the report is complete.

---

## Step 2. Fix Backend Issues (if any found in Step 1)

### 2A. CORS — add to backend/main.py if missing

```python
# backend/main.py
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://frontend:3000",       # container-to-container
        "http://localhost:80",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 2B. Health endpoint — add if missing

```python
# backend/api/health.py
from fastapi import APIRouter

router = APIRouter()

@router.get("/api/health")
async def health():
    return {"status": "ok"}
```

### 2C. Run creation — verify request schema matches frontend

```python
# backend/schemas/run.py  (verify this matches what NewRun.tsx sends)
class CreateRunRequest(BaseModel):
    name: str
    build_command: str | None = None
    codeql_build_mode: str = "autodetect"
    T_max: int = 60
    T_explore: int = 8
    T_author: int = 12
    T_klee: int = 300
    R_max: int = 15
    parallelism: int = 128
    run_phase3: bool = True
```

### 2D. SSE token auth — verify query param accepted

```python
# backend/api/events.py
from fastapi import Query
from services.auth_service import verify_token

@router.get("/api/events")
async def events(
    topics: str = Query(...),
    token: str = Query(None),           # browser EventSource uses ?token=
    authorization: str = Header(None),  # axios uses Authorization header
):
    # Accept token from either source
    raw = token or (authorization or "").removeprefix("Bearer ").strip()
    user = verify_token(raw)  # raises 401 if invalid
    ...
```

---

## Step 3. Fix Frontend Issues

Fix in this order. Each fix is independent — apply all that are needed.

### 3A. api/client.ts — fix base URL and token injection

```typescript
// frontend/src/api/client.ts

import axios from 'axios'

// VITE_API_URL is set at build time.
// In Docker: nginx proxies /api/ → backend:8000, so just use ''
// In dev:    vite.config.ts proxies /api/ → localhost:8000
const BASE_URL = import.meta.env.VITE_API_URL ?? ''

export const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// Inject auth token on every request
apiClient.interceptors.request.use((config) => {
  // Read from Zustand persisted storage
  const stored = localStorage.getItem('sailor-auth')
  const token = stored ? JSON.parse(stored)?.state?.token : null
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle auth errors globally
apiClient.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('sailor-auth')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)
```

### 3B. api/runs.ts — fix createRun and add error details

```typescript
// frontend/src/api/runs.ts

import { apiClient } from './client'

export interface CreateRunPayload {
  name: string
  build_command?: string
  codeql_build_mode?: 'autodetect' | 'none' | 'custom'
  T_max?: number
  T_explore?: number
  T_author?: number
  T_klee?: number
  R_max?: number
  parallelism?: number
  run_phase3?: boolean
}

export async function createRun(
  payload: CreateRunPayload,
  zipFile?: File,
): Promise<{ id: string; status: string }> {

  if (zipFile) {
    // Multipart form upload
    const form = new FormData()
    form.append('file', zipFile)
    form.append('config', JSON.stringify(payload))
    const res = await apiClient.post('/api/runs', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return res.data
  }

  // JSON-only (no zip) — for testing without a project
  const res = await apiClient.post('/api/runs', payload)
  return res.data
}

export async function getRun(runId: string) {
  const res = await apiClient.get(`/api/runs/${runId}`)
  return res.data
}

export async function listRuns(params?: {
  status?: string
  cursor?: string
  page_size?: number
}) {
  const res = await apiClient.get('/api/runs', { params })
  return res.data
}
```

### 3C. NewRun.tsx — fix form submit handler

The most common cause of "nothing happens" on submit is:
- Missing `onSubmit` handler
- Handler not calling `e.preventDefault()`
- `navigate()` not called after successful run creation
- Error swallowed silently

```tsx
// frontend/src/pages/NewRun.tsx

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createRun } from '../api/runs'

export function NewRun() {
  const navigate  = useNavigate()
  const [name, setName]               = useState('')
  const [buildCommand, setBuildCmd]   = useState('')
  const [zipFile, setZipFile]         = useState<File | null>(null)
  const [isSubmitting, setSubmitting] = useState(false)
  const [error, setError]             = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()           // ← CRITICAL: prevents page reload
    if (!name.trim()) {
      setError('Project name is required.')
      return
    }

    setSubmitting(true)
    setError(null)

    try {
      const run = await createRun(
        { name: name.trim(), build_command: buildCommand || undefined },
        zipFile ?? undefined,
      )
      // Navigate to the new run's detail page
      navigate(`/runs/${run.id}`)
    } catch (err: any) {
      // Show the actual error — never swallow silently
      const msg =
        err?.response?.data?.detail ??
        err?.response?.data?.message ??
        err?.message ??
        'Unknown error creating run.'
      setError(msg)
      console.error('[NewRun] createRun failed:', err)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto p-6">
      <h1 className="text-2xl font-bold text-white mb-6">New Run</h1>

      {error && (
        <div className="mb-4 p-3 bg-red-950 border border-red-700
                        rounded-lg text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* Use a real <form> with onSubmit — not onClick on a button */}
      <form onSubmit={handleSubmit} className="space-y-5">

        <div>
          <label className="block text-sm text-gray-400 mb-1">
            Project name *
          </label>
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            required
            placeholder="e.g. binutils-2.40"
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700
                       rounded-md text-white focus:outline-none
                       focus:border-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">
            Build command (leave blank for autodetect)
          </label>
          <input
            type="text"
            value={buildCommand}
            onChange={e => setBuildCmd(e.target.value)}
            placeholder="e.g. bear -- make -j4"
            className="w-full px-3 py-2 bg-gray-800 border border-gray-700
                       rounded-md text-white focus:outline-none
                       focus:border-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">
            Project zip (optional for testing)
          </label>
          <input
            type="file"
            accept=".zip"
            onChange={e => setZipFile(e.target.files?.[0] ?? null)}
            className="block w-full text-sm text-gray-400
                       file:mr-4 file:py-2 file:px-4
                       file:rounded-md file:border-0
                       file:bg-gray-700 file:text-gray-200
                       hover:file:bg-gray-600"
          />
        </div>

        <button
          type="submit"
          disabled={isSubmitting}
          className="w-full py-2.5 bg-blue-600 hover:bg-blue-500
                     disabled:bg-blue-800 disabled:cursor-not-allowed
                     text-white font-medium rounded-md transition-colors"
        >
          {isSubmitting ? 'Creating run…' : 'Start run'}
        </button>
      </form>
    </div>
  )
}
```

### 3D. RunDetail.tsx — fix live progress display

The most common causes of "no live progress":
- SSE not subscribed (useSSE not called or wrong topic)
- SSE events received but state not updated
- Counters displayed from stale initial fetch (not updated via SSE)

```tsx
// frontend/src/pages/RunDetail.tsx

import { useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSSE } from '../hooks/useSSE'
import { getRun } from '../api/runs'

export function RunDetail() {
  const { run_id } = useParams<{ run_id: string }>()
  const queryClient = useQueryClient()

  // Initial fetch
  const { data: run, isLoading, isError } = useQuery({
    queryKey: ['run', run_id],
    queryFn: () => getRun(run_id!),
    enabled: !!run_id,
    staleTime: 5_000,
  })

  // Live updates via SSE
  // Subscribe to both the run topic AND the specs topic
  useSSE({
    topics: [
      `runs.${run_id}`,
      `runs.${run_id}.specs`,
    ],
    onEvent: (event) => {
      // On any run-level event, invalidate the run query
      // so it refetches the latest counters
      if (
        event.kind === 'run_status_changed' ||
        event.kind === 'run_counters_updated'
      ) {
        queryClient.invalidateQueries({ queryKey: ['run', run_id] })
      }

      // Patch run data directly for counter diffs (faster, no refetch)
      if (event.kind === 'run_counters_updated' && event.counters) {
        queryClient.setQueryData(['run', run_id], (old: any) =>
          old ? { ...old, counters: { ...old.counters, ...event.counters } }
              : old
        )
      }
    },
  })

  if (!run_id) return null

  if (isLoading) {
    return (
      <div className="p-6 space-y-3">
        <div className="h-8 w-48 bg-gray-800 rounded animate-pulse" />
        <div className="h-28 bg-gray-800 rounded-xl animate-pulse" />
        <div className="h-64 bg-gray-800 rounded-xl animate-pulse" />
      </div>
    )
  }

  if (isError || !run) {
    return (
      <div className="p-6">
        <div className="p-4 bg-red-950 border border-red-700
                        rounded-xl text-red-400 text-sm">
          Failed to load run {run_id}. Check the backend logs.
        </div>
      </div>
    )
  }

  const { counters } = run

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">{run.name}</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {run.project_ref} · Started {new Date(run.started_at ?? run.created_at).toLocaleString()}
          </p>
        </div>
        <RunStatusBadge status={run.status} />
      </div>

      {/* Live progress bars */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">

        <PhaseProgress
          label="Phase 1"
          done={counters.phase1_done}
          total={counters.total_specs}
          color="blue"
        />

        <PhaseProgress
          label="Phase 2"
          done={counters.phase2_done}
          total={counters.phase1_done}
          color="indigo"
          detail={`${counters.bug_triggered} triggered · ${counters.inconclusive} inconclusive · ${counters.likely_fp} likely FP`}
        />

        <PhaseProgress
          label="Phase 3"
          done={counters.confirmed}
          total={counters.bug_triggered}
          color="green"
          detail={`${counters.confirmed} confirmed`}
        />

        <div className="pt-2 border-t border-gray-800 flex gap-6 text-xs text-gray-500">
          <span>Total specs: {counters.total_specs}</span>
          <span>LLM cost: ~${counters.token_cost_usd?.toFixed(3) ?? '0.000'}</span>
        </div>
      </div>

      {/* Run controls */}
      <RunControls runId={run_id} status={run.status} />

    </div>
  )
}

function PhaseProgress({
  label, done, total, color, detail
}: {
  label: string
  done: number
  total: number
  color: 'blue' | 'indigo' | 'green'
  detail?: string
}) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0
  const barColor = {
    blue:   'bg-blue-500',
    indigo: 'bg-indigo-500',
    green:  'bg-green-500',
  }[color]

  return (
    <div>
      <div className="flex justify-between text-sm mb-1">
        <span className="text-gray-300 font-medium">{label}</span>
        <span className="text-gray-400">{done} / {total > 0 ? total : '?'}</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {detail && (
        <p className="text-xs text-gray-600 mt-1">{detail}</p>
      )}
    </div>
  )
}

function RunStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    running:   'bg-blue-500/20 text-blue-400 animate-pulse',
    completed: 'bg-green-500/20 text-green-400',
    failed:    'bg-red-500/20 text-red-400',
    paused:    'bg-yellow-500/20 text-yellow-400',
    queued:    'bg-gray-500/20 text-gray-400',
    cancelled: 'bg-gray-700/20 text-gray-500',
  }
  return (
    <span className={`px-3 py-1 rounded-full text-xs font-medium ${map[status] ?? 'bg-gray-700 text-gray-400'}`}>
      {status}
    </span>
  )
}

function RunControls({ runId, status }: { runId: string; status: string }) {
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)

  const action = async (verb: string) => {
    setError(null)
    try {
      await apiClient.post(`/api/runs/${runId}/${verb}`)
      queryClient.invalidateQueries({ queryKey: ['run', runId] })
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? `Failed to ${verb} run.`)
    }
  }

  return (
    <div className="flex gap-3">
      {status === 'running' && (
        <button onClick={() => action('pause')}
                className="px-4 py-2 bg-yellow-600 hover:bg-yellow-500
                           text-white text-sm rounded-md">
          Pause
        </button>
      )}
      {status === 'paused' && (
        <button onClick={() => action('resume')}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500
                           text-white text-sm rounded-md">
          Resume
        </button>
      )}
      {['running', 'paused', 'queued'].includes(status) && (
        <button onClick={() => action('cancel')}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600
                           text-white text-sm rounded-md">
          Cancel
        </button>
      )}
      {error && (
        <span className="text-red-400 text-sm self-center">{error}</span>
      )}
    </div>
  )
}
```

### 3E. hooks/useSSE.ts — fix subscription and reconnect

```typescript
// frontend/src/hooks/useSSE.ts

import { useEffect, useRef } from 'react'

interface UseSSEOptions {
  topics: string[]
  onEvent: (event: any) => void
}

export function useSSE({ topics, onEvent }: UseSSEOptions) {
  const esRef         = useRef<EventSource | null>(null)
  const onEventRef    = useRef(onEvent)
  const lastEventId   = useRef<string | undefined>(undefined)
  const retryDelay    = useRef(1000)
  const retryTimeout  = useRef<ReturnType<typeof setTimeout>>()

  // Keep callback ref current without re-subscribing
  onEventRef.current = onEvent

  useEffect(() => {
    if (topics.length === 0) return

    const token = (() => {
      const stored = localStorage.getItem('sailor-auth')
      return stored ? JSON.parse(stored)?.state?.token : null
    })()

    if (!token) return

    const connect = () => {
      const params = new URLSearchParams({
        topics: topics.join(','),
        token,
        ...(lastEventId.current
          ? { since: lastEventId.current }
          : {}),
      })

      const es = new EventSource(`/api/events?${params}`)
      esRef.current = es

      es.onmessage = (e) => {
        retryDelay.current = 1000  // reset backoff on success
        if (e.lastEventId) lastEventId.current = e.lastEventId

        try {
          const data = JSON.parse(e.data)

          // Handle resync_required: force full page refetch
          if (data.kind === 'resync_required') {
            console.warn('[SSE] resync_required — reloading data')
            onEventRef.current({ kind: 'resync_required' })
            return
          }

          onEventRef.current(data)
        } catch {
          // ignore malformed events
        }
      }

      es.onerror = () => {
        es.close()
        esRef.current = null
        // Exponential backoff: 1s → 2s → 4s → … → 30s max
        retryTimeout.current = setTimeout(() => {
          retryDelay.current = Math.min(retryDelay.current * 2, 30_000)
          connect()
        }, retryDelay.current)
      }
    }

    connect()

    return () => {
      clearTimeout(retryTimeout.current)
      esRef.current?.close()
      esRef.current = null
    }
  // Re-subscribe only when topics change (not onEvent)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topics.join(',')])
}
```

### 3F. TanStack Query provider — ensure it wraps the app

```tsx
// frontend/src/main.tsx

import { StrictMode }         from 'react'
import { createRoot }         from 'react-dom/client'
import { QueryClient,
         QueryClientProvider } from '@tanstack/react-query'
import App                    from './App'
import { useAuth }            from './hooks/useAuth'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 10_000,
    },
  },
})

// Resolve persisted auth before first render
useAuth.getState().init()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>
)
```

---

## Step 4. Add Error Detection Layer

These additions ensure errors are always visible — never silent.

### 4A. Global error toast

```tsx
// frontend/src/components/ErrorToast.tsx

import { useEffect, useState } from 'react'

// Simple event bus for global errors
type ToastMessage = { id: number; message: string; type: 'error' | 'warning' }

const listeners = new Set<(msg: ToastMessage) => void>()
let nextId = 0

export function showError(message: string) {
  const msg = { id: nextId++, message, type: 'error' as const }
  listeners.forEach(fn => fn(msg))
}

export function showWarning(message: string) {
  const msg = { id: nextId++, message, type: 'warning' as const }
  listeners.forEach(fn => fn(msg))
}

export function ErrorToastContainer() {
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  useEffect(() => {
    const handler = (msg: ToastMessage) => {
      setToasts(prev => [...prev, msg])
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== msg.id))
      }, 6000)
    }
    listeners.add(handler)
    return () => { listeners.delete(handler) }
  }, [])

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2
                    max-w-sm w-full">
      {toasts.map(t => (
        <div key={t.id}
             className={`flex items-start gap-3 p-4 rounded-xl shadow-lg
                         border text-sm
                         ${t.type === 'error'
                           ? 'bg-red-950 border-red-700 text-red-300'
                           : 'bg-yellow-950 border-yellow-700 text-yellow-300'
                         }`}>
          <span>{t.type === 'error' ? '✕' : '⚠'}</span>
          <span className="flex-1">{t.message}</span>
          <button
            onClick={() => setToasts(p => p.filter(x => x.id !== t.id))}
            className="text-gray-500 hover:text-gray-300"
          >
            ×
          </button>
        </div>
      ))}
    </div>
  )
}
```

Add `<ErrorToastContainer />` to `AppShell.tsx`:

```tsx
// frontend/src/components/AppShell.tsx  (add inside the outer div)
import { ErrorToastContainer } from './ErrorToast'

// Inside the JSX:
<ErrorToastContainer />
```

Update `api/client.ts` to use it:

```typescript
// api/client.ts — add after imports
import { showError } from '../components/ErrorToast'

// In the response interceptor:
apiClient.interceptors.response.use(
  (res) => res,
  (err) => {
    const status  = err?.response?.status
    const detail  = err?.response?.data?.detail ?? err?.message ?? 'Unknown error'

    if (status === 401) {
      localStorage.removeItem('sailor-auth')
      window.location.href = '/login'
    } else if (status === 422) {
      showError(`Validation error: ${JSON.stringify(detail)}`)
    } else if (status >= 500) {
      showError(`Server error ${status}: ${detail}`)
    } else if (!err.response) {
      showError('Cannot reach backend. Check that docker compose is running.')
    }

    console.error('[API]', err?.config?.url, status, detail)
    return Promise.reject(err)
  }
)
```

### 4B. SSE connection status indicator

```tsx
// frontend/src/components/SSEStatusIndicator.tsx

import { useEffect, useState } from 'react'

// Add to AppShell sidebar footer or Run Detail header
export function SSEStatusIndicator({ topics }: { topics: string[] }) {
  const [connected, setConnected] = useState(false)

  // Subscribe to a meta-event emitted by useSSE
  // (requires adding onConnect/onDisconnect callbacks to useSSE)

  return (
    <div className="flex items-center gap-1.5 text-xs">
      <div className={`w-1.5 h-1.5 rounded-full
                       ${connected ? 'bg-green-400' : 'bg-yellow-400 animate-pulse'}`} />
      <span className="text-gray-500">
        {connected ? 'Live' : 'Reconnecting…'}
      </span>
    </div>
  )
}
```

Extend `useSSE` to call `onConnect`/`onDisconnect` callbacks:

```typescript
// Add to UseSSEOptions interface:
onConnect?: () => void
onDisconnect?: () => void

// In connect():
es.onopen = () => options.onConnect?.()
es.onerror = () => {
  options.onDisconnect?.()
  // ... existing retry logic
}
```

### 4C. React Error Boundary — catch render crashes

```tsx
// frontend/src/components/ErrorBoundary.tsx

import { Component, ReactNode } from 'react'

interface Props { children: ReactNode; fallback?: ReactNode }
interface State { hasError: boolean; error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: any) {
    console.error('[ErrorBoundary]', error, info)
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback ?? (
        <div className="p-6">
          <div className="p-4 bg-red-950 border border-red-700
                          rounded-xl text-sm">
            <p className="text-red-400 font-medium mb-2">
              Something went wrong
            </p>
            <pre className="text-red-600 text-xs overflow-auto">
              {this.state.error?.message}
            </pre>
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="mt-3 text-xs text-red-400 underline"
            >
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
```

Wrap each route in `App.tsx`:

```tsx
<Route path="/runs/:run_id" element={
  <ErrorBoundary>
    <RunDetail />
  </ErrorBoundary>
} />
```

---

## Step 5. Verify Everything

After all fixes are applied:

```bash
# 1. Rebuild frontend
docker compose up -d --build frontend

# 2. Watch logs during test
docker compose logs -f frontend backend worker 2>&1 | tee /tmp/sailor_logs.txt &

# 3. Backend smoke test
curl -s http://localhost:8000/api/health
# Expected: {"status":"ok"}

# 4. Frontend smoke test
curl -s -I http://localhost:3000
# Expected: HTTP 200

# 5. API proxy smoke test
curl -s http://localhost:3000/api/health
# Expected: {"status":"ok"}

# 6. Login + run creation test
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<your_password>"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

RUN_ID=$(curl -s -X POST http://localhost:8000/api/runs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"smoke-test"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

echo "Created run: $RUN_ID"
curl -s "http://localhost:8000/api/runs/$RUN_ID" \
  -H "Authorization: Bearer $TOKEN"

# 7. SSE test
curl -s -N "http://localhost:8000/api/events?topics=runs.all&token=$TOKEN" \
  --max-time 5

# 8. Browser checks:
# a. Open http://localhost:3000 → should redirect to /login
# b. Login → should land on Dashboard
# c. Click "New Run" → fill form → click "Start run"
#    → should show "Creating run…" then navigate to /runs/:id
# d. /runs/:id → should show three phase progress bars
#    → bars update in real time if a run is active
#    → "Live" indicator in green if SSE connected
```

### Expected Results Checklist

```
□ http://localhost:3000 redirects to /login (not blank)
□ Login → Dashboard with sidebar visible
□ "New Run" form submits → navigates to /runs/:id
□ Error shown in red if submit fails (not silent)
□ /runs/:id shows Phase 1/2/3 progress bars
□ Progress bars update without page refresh while run is active
□ SSE "Live" indicator shown in green
□ SSE "Reconnecting…" shown if backend restarts
□ Any API error shows toast (not silent)
□ Render crash shows ErrorBoundary (not blank)
□ Hard refresh on /runs/:id works (not blank)
□ Console has zero unhandled promise rejections
```

---

## Step 6. Run Standard Last Step

Append to CLAUDE_feedback.md per Standard Last Step.
