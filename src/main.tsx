import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

// Service-worker kill switch (plan §8.6: no offline support). Older deploys
// registered a caching worker; unregister every remaining worker and drop
// its caches so nothing stale — and no decrypted content — survives on disk.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    void (async () => {
      try {
        const registrations = await navigator.serviceWorker.getRegistrations()
        await Promise.all(registrations.map((registration) => registration.unregister()))
        if (typeof caches !== 'undefined') {
          const cacheKeys = await caches.keys()
          await Promise.all(cacheKeys.map((key) => caches.delete(key)))
        }
      } catch {
        // The kill switch is best-effort; a failed unregister retries on
        // the next load.
      }
    })()
  })
}
