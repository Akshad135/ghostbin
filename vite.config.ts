import { defineConfig, loadEnv, createLogger } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import fs from 'fs'
import type { ServerResponse } from 'node:http'

// Custom logger — suppress Vite's built-in red proxy error stack traces
const logger = createLogger()
const originalError = logger.error.bind(logger)
logger.error = (msg, options) => {
  // Our configure() handler already logs a clean yellow warning
  if (typeof msg === 'string' && msg.includes('http proxy error')) return
  originalError(msg, options)
}

/**
 * Reads config.yaml and returns a flat Record<string, string>.
 * Handles only simple `key: value` lines (no nesting needed).
 */
function loadYamlConfig(filePath: string): Record<string, string> {
  if (!fs.existsSync(filePath)) return {}
  const content = fs.readFileSync(filePath, 'utf-8')
  const result: Record<string, string> = {}
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const idx = trimmed.indexOf(':')
    if (idx === -1) continue
    const key = trimmed.slice(0, idx).trim()
    let value = trimmed.slice(idx + 1).trim()
    // Strip surrounding quotes if present
    if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    result[key] = value
  }
  return result
}

/**
 * Maps YAML snake_case keys → VITE_* env var names.
 */
const YAML_TO_ENV: Record<string, string> = {
  app_name: 'VITE_APP_NAME',
  app_name_accent: 'VITE_APP_NAME_ACCENT',
  app_description: 'VITE_APP_DESCRIPTION',
  favicon_url: 'VITE_FAVICON_URL',
  apple_touch_icon: 'VITE_APPLE_TOUCH_ICON',
}

export default defineConfig(({ mode }) => {
  // 1. Load config.yaml → VITE_* env vars (committed defaults)
  const yamlConfig = loadYamlConfig(path.resolve(__dirname, 'config.yaml'))
  for (const [yamlKey, envKey] of Object.entries(YAML_TO_ENV)) {
    if (yamlConfig[yamlKey] && !process.env[envKey]) {
      process.env[envKey] = yamlConfig[yamlKey]
    }
  }

  // 2. Load .env / .env.local (secrets + overrides)
  const env = loadEnv(mode, process.cwd(), '')
  Object.assign(process.env, env)

  return {
    customLogger: logger,
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      proxy: {
        // Proxy HTTP and WebSocket API traffic so cookies stay same-origin.
        '/api': {
          target: 'http://127.0.0.1:8788',
          changeOrigin: true,
          ws: true,
          cookieDomainRewrite: { '*': '' },
          configure: (proxy) => {
            // The backend's WebSocket same-origin check compares Origin to
            // Host. The browser sends the Vite origin, so rewrite it to match
            // the proxied backend host.
            proxy.on('proxyReqWs', (proxyReq) => {
              proxyReq.setHeader('origin', 'http://127.0.0.1:8788')
            })
            proxy.on('error', (err, _req, res) => {
              const code = (err as NodeJS.ErrnoException).code
              console.warn(`\x1b[33m[api] Backend unavailable (${code || err.message}) — is dev:api running?\x1b[0m`)
              if (res && 'writeHead' in res && !res.headersSent) {
                const response = res as ServerResponse
                response.writeHead(502, { 'Content-Type': 'application/json' })
                response.end(JSON.stringify({ error: 'Backend unavailable' }))
              }
            })
          },
        },
      },
    },
  }
})
