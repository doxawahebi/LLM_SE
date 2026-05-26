type ToastMessage = { id: number; message: string; type: 'error' | 'warning' }

export const toastListeners = new Set<(msg: ToastMessage) => void>()
let nextId = 0

export function showError(message: string) {
  const msg: ToastMessage = { id: nextId++, message, type: 'error' }
  toastListeners.forEach((fn) => fn(msg))
}

export function showWarning(message: string) {
  const msg: ToastMessage = { id: nextId++, message, type: 'warning' }
  toastListeners.forEach((fn) => fn(msg))
}

export type { ToastMessage }
