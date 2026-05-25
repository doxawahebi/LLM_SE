import { useEffect, useState } from 'react'

type ToastMessage = { id: number; message: string; type: 'error' | 'warning' }

const listeners = new Set<(msg: ToastMessage) => void>()
let nextId = 0

export function showError(message: string) {
  const msg: ToastMessage = { id: nextId++, message, type: 'error' }
  listeners.forEach((fn) => fn(msg))
}

export function showWarning(message: string) {
  const msg: ToastMessage = { id: nextId++, message, type: 'warning' }
  listeners.forEach((fn) => fn(msg))
}

export function ErrorToastContainer() {
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  useEffect(() => {
    const handler = (msg: ToastMessage) => {
      setToasts((prev) => [...prev, msg])
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== msg.id))
      }, 6000)
    }
    listeners.add(handler)
    return () => { listeners.delete(handler) }
  }, [])

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`flex items-start gap-3 p-3 rounded-lg shadow-lg border text-sm pointer-events-auto ${
            t.type === 'error'
              ? 'bg-red-950/90 border-red-700/50 text-red-300'
              : 'bg-yellow-950/90 border-yellow-700/50 text-yellow-300'
          }`}
        >
          <span className="shrink-0">{t.type === 'error' ? '✕' : '⚠'}</span>
          <span className="flex-1 break-words">{t.message}</span>
          <button
            onClick={() => setToasts((p) => p.filter((x) => x.id !== t.id))}
            className="shrink-0 opacity-50 hover:opacity-100 transition-opacity"
          >
            ×
          </button>
        </div>
      ))}
    </div>
  )
}
