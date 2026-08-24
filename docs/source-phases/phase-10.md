# PHASE 10: Frontend Setup & Structure

Building the React + TypeScript frontend with Tailwind CSS.

---

## 📁 File 96: `frontend/package.json`

```
JSON
```

```
{
  "name": "advanced-ids-frontend",
  "version": "1.0.0",
  "description": "Advanced IDS - SOC Dashboard Frontend",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "axios": "^1.6.2",
    "recharts": "^2.10.3",
    "date-fns": "^2.30.0",
    "lucide-react": "^0.294.0",
    "react-hot-toast": "^2.4.1",
    "zustand": "^4.4.7"
  },
  "devDependencies": {
    "@types/react": "^18.2.43",
    "@types/react-dom": "^18.2.17",
    "@typescript-eslint/eslint-plugin": "^6.14.0",
    "@typescript-eslint/parser": "^6.14.0",
    "@vitejs/plugin-react": "^4.2.1",
    "autoprefixer": "^10.4.16",
    "eslint": "^8.55.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.4.5",
    "postcss": "^8.4.32",
    "tailwindcss": "^3.3.6",
    "typescript": "^5.2.2",
    "vite": "^5.0.8"
  }
}
```

---

## 📁 File 97: `frontend/tsconfig.json`

```
JSON
```

```
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,

    /* Bundler mode */
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",

    /* Linting */
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,

    /* Path aliases */
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

---

## 📁 File 98: `frontend/tsconfig.node.json`

```
JSON
```

```
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
```

---

## 📁 File 99: `frontend/vite.config.ts`

```
TypeScript
```

```
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
```

---

## 📁 File 100: `frontend/tailwind.config.js`

```
JavaScript
```

```
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Dark cybersecurity theme
        primary: {
          50: '#e6f9ff',
          100: '#b3ecff',
          200: '#80dfff',
          300: '#4dd2ff',
          400: '#1ac5ff',
          500: '#00b8e6',
          600: '#0099cc',
          700: '#007ab3',
          800: '#005b99',
          900: '#003c80',
        },
        dark: {
          50: '#2a3150',
          100: '#252b45',
          200: '#1f243a',
          300: '#1a1f35',
          400: '#151a2e',
          500: '#101427',
          600: '#0d1120',
          700: '#0a0e1a',
          800: '#070b13',
          900: '#04070d',
        },
        success: {
          DEFAULT: '#00ff88',
          dark: '#00cc6a',
        },
        warning: {
          DEFAULT: '#ffaa00',
          dark: '#cc8800',
        },
        danger: {
          DEFAULT: '#ff3366',
          dark: '#cc2952',
        },
        critical: {
          DEFAULT: '#ff0044',
          dark: '#cc0036',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.3s ease-in',
        'slide-in': 'slideIn 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
```

---

## 📁 File 101: `frontend/postcss.config.js`

```
JavaScript
```

```
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
```

---

## 📁 File 102: `frontend/index.html`

```
HTML
```

```
<!doctype html>
<html lang="en" class="dark">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/shield-icon.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Advanced IDS - Network Security Monitoring</title>
  </head>
  <body class="bg-dark-900 text-gray-100">
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

---

## 📁 File 103: `frontend/src/main.tsx`

```
TypeScript
```

```
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#1a1f35',
            color: '#fff',
            border: '1px solid #2a3150',
          },
          success: {
            iconTheme: {
              primary: '#00ff88',
              secondary: '#1a1f35',
            },
          },
          error: {
            iconTheme: {
              primary: '#ff3366',
              secondary: '#1a1f35',
            },
          },
        }}
      />
    </BrowserRouter>
  </React.StrictMode>,
)
```

---

## 📁 File 104: `frontend/src/index.css`

```
CSS
```

```
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  * {
    @apply border-dark-50;
  }

  body {
    @apply font-sans antialiased;
  }

  /* Custom scrollbar */
  ::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  ::-webkit-scrollbar-track {
    @apply bg-dark-800;
  }

  ::-webkit-scrollbar-thumb {
    @apply bg-dark-200 rounded;
  }

  ::-webkit-scrollbar-thumb:hover {
    @apply bg-dark-100;
  }
}

@layer components {
  /* Buttons */
  .btn {
    @apply px-4 py-2 rounded-lg font-medium transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-dark-900;
  }

  .btn-primary {
    @apply bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500;
  }

  .btn-secondary {
    @apply bg-dark-200 text-gray-300 hover:bg-dark-100 focus:ring-dark-50;
  }

  .btn-danger {
    @apply bg-danger text-white hover:bg-danger-dark focus:ring-danger;
  }

  .btn-success {
    @apply bg-success text-dark-900 hover:bg-success-dark focus:ring-success;
  }

  /* Cards */
  .card {
    @apply bg-dark-300 rounded-lg border border-dark-50 shadow-lg;
  }

  .card-body {
    @apply p-6;
  }

  /* Inputs */
  .input {
    @apply w-full px-4 py-2 bg-dark-400 border border-dark-50 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent;
  }

  /* Badges */
  .badge {
    @apply inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium;
  }

  .badge-info {
    @apply bg-blue-900 text-blue-200;
  }

  .badge-low {
    @apply bg-gray-700 text-gray-300;
  }

  .badge-medium {
    @apply bg-yellow-900 text-yellow-200;
  }

  .badge-high {
    @apply bg-orange-900 text-orange-200;
  }

  .badge-critical {
    @apply bg-red-900 text-red-200;
  }

  /* Status badges */
  .badge-new {
    @apply bg-blue-900 text-blue-200;
  }

  .badge-acknowledged {
    @apply bg-yellow-900 text-yellow-200;
  }

  .badge-investigating {
    @apply bg-orange-900 text-orange-200;
  }

  .badge-resolved {
    @apply bg-green-900 text-green-200;
  }

  .badge-false-positive {
    @apply bg-gray-700 text-gray-300;
  }
}

/* Animations */
.animate-pulse-glow {
  animation: pulse-glow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

@keyframes pulse-glow {
  0%, 100% {
    opacity: 1;
    box-shadow: 0 0 10px rgba(0, 217, 255, 0.5);
  }
  50% {
    opacity: 0.7;
    box-shadow: 0 0 20px rgba(0, 217, 255, 0.8);
  }
}

/* Live indicator */
.live-indicator {
  @apply relative inline-flex h-3 w-3;
}

.live-indicator::before {
  @apply absolute inline-flex h-full w-full rounded-full bg-success opacity-75;
  content: '';
  animation: ping 1.5s cubic-bezier(0, 0, 0.2, 1) infinite;
}

.live-indicator::after {
  @apply relative inline-flex rounded-full h-3 w-3 bg-success;
  content: '';
}

@keyframes ping {
  75%, 100% {
    transform: scale(2);
    opacity: 0;
  }
}
```

---

## 📁 File 105: `frontend/src/types/index.ts`

```
TypeScript
```

```
// Common types used across the application

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type AlertStatus = 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive'

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved'

export interface User {
  id: number
  username: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  created_at: string
  last_login?: string
}

export interface Alert {
  id: number
  alert_uuid: string
  rule_id?: string
  title: string
  description?: string
  category?: string
  severity: Severity
  confidence?: number
  src_ip?: string
  dst_ip?: string
  src_port?: number
  dst_port?: number
  protocol?: string
  evidence?: Record<string, any>
  mitre_attack_id?: string
  timestamp: string
  status: AlertStatus
  assigned_to?: number
  resolution_notes?: string
  resolved_at?: string
  resolved_by?: number
}

export interface Incident {
  id: number
  incident_uuid: string
  title: string
  description?: string
  severity: Severity
  risk_score: number
  status: IncidentStatus
  src_ip?: string
  dst_ips?: string[]
  attack_chain?: any
  first_seen: string
  last_seen: string
  alert_count: number
  affected_hosts: number
  mitre_techniques?: string[]
  assigned_to?: number
  created_at: string
  resolved_at?: string
}

export interface DashboardStats {
  packets_analyzed: number
  active_flows: number
  alerts_today: number
  critical_alerts: number
  high_risk_sources: number
  total_bytes: number
  events_per_second: number
}

export interface TimeSeriesData {
  timestamp: string
  value: number
  label?: string
}

export interface ProtocolDistribution {
  protocol: string
  count: number
  percentage: number
}

export interface TopHost {
  ip_address: string
  packets?: number
  bytes?: number
  flow_count?: number
  alert_count?: number
  risk_score?: number
}

export interface WebSocketMessage {
  type: 'connection_established' | 'new_alert' | 'incident_update' | 'stats_update' | 'flow_update' | 'system_message' | 'pong'
  data?: any
  message?: string
  timestamp: string
  level?: 'info' | 'warning' | 'error'
}
```

---

## 📁 File 106: `frontend/src/lib/api.ts`

```
TypeScript
```

```
import axios, { AxiosInstance, InternalAxiosRequestConfig } from 'axios'
import { toast } from 'react-hot-toast'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor - add auth token
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem('access_token')
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor - handle errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    // If 401 and not already retried, try to refresh token
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        const refreshToken = localStorage.getItem('refresh_token')
        if (refreshToken) {
          const response = await axios.post(`${API_BASE_URL}/api/v1/auth/refresh`, {
            refresh_token: refreshToken,
          })

          const { access_token, refresh_token: newRefreshToken } = response.data

          localStorage.setItem('access_token', access_token)
          localStorage.setItem('refresh_token', newRefreshToken)

          originalRequest.headers.Authorization = `Bearer ${access_token}`
          return api(originalRequest)
        }
      } catch (refreshError) {
        // Refresh failed, logout user
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        window.location.href = '/login'
        return Promise.reject(refreshError)
      }
    }

    // Show error toast for other errors
    const message = error.response?.data?.detail || error.message || 'An error occurred'
    toast.error(message)

    return Promise.reject(error)
  }
)

export default api
```

---

## 📁 File 107: `frontend/src/lib/websocket.ts`

```
TypeScript
```

```
import { WebSocketMessage } from '@/types'

const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000'

export class WebSocketClient {
  private ws: WebSocket | null = null
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectDelay = 3000
  private listeners: Map<string, Set<(data: any) => void>> = new Map()
  private isConnecting = false

  constructor(private endpoint: string = '/api/v1/ws/events') {}

  connect(token?: string): void {
    if (this.ws?.readyState === WebSocket.OPEN || this.isConnecting) {
      return
    }

    this.isConnecting = true
    const url = token 
      ? `${WS_BASE_URL}${this.endpoint}?token=${token}`
      : `${WS_BASE_URL}${this.endpoint}`

    console.log('Connecting to WebSocket:', url)

    this.ws = new WebSocket(url)

    this.ws.onopen = () => {
      console.log('WebSocket connected')
      this.isConnecting = false
      this.reconnectAttempts = 0
      this.emit('connected', {})
    }

    this.ws.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data)
        this.handleMessage(message)
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      this.isConnecting = false
    }

    this.ws.onclose = () => {
      console.log('WebSocket disconnected')
      this.isConnecting = false
      this.ws = null
      this.emit('disconnected', {})
      this.attemptReconnect(token)
    }
  }

  private handleMessage(message: WebSocketMessage): void {
    // Emit to type-specific listeners
    this.emit(message.type, message.data || message)

    // Emit to general message listener
    this.emit('message', message)
  }

  private attemptReconnect(token?: string): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('Max reconnection attempts reached')
      return
    }

    this.reconnectAttempts++
    console.log(`Reconnecting... Attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`)

    setTimeout(() => {
      this.connect(token)
    }, this.reconnectDelay * this.reconnectAttempts)
  }

  on(event: string, callback: (data: any) => void): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set())
    }
    this.listeners.get(event)!.add(callback)
  }

  off(event: string, callback: (data: any) => void): void {
    const listeners = this.listeners.get(event)
    if (listeners) {
      listeners.delete(callback)
    }
  }

  private emit(event: string, data: any): void {
    const listeners = this.listeners.get(event)
    if (listeners) {
      listeners.forEach((callback) => callback(data))
    }
  }

  send(data: any): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(typeof data === 'string' ? data : JSON.stringify(data))
    } else {
      console.warn('WebSocket is not connected')
    }
  }

  ping(): void {
    this.send('ping')
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }
}

// Global WebSocket instance
export const wsClient = new WebSocketClient()
```

---

## 📁 File 108: `frontend/src/store/authStore.ts`

```
TypeScript
```

```
import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import api from '@/lib/api'
import { User } from '@/types'
import { toast } from 'react-hot-toast'

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  fetchCurrentUser: () => Promise<void>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      isLoading: false,

      login: async (username: string, password: string) => {
        set({ isLoading: true })
        try {
          const formData = new FormData()
          formData.append('username', username)
          formData.append('password', password)

          const response = await api.post('/auth/login', formData, {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
          })

          const { access_token, refresh_token } = response.data

          localStorage.setItem('access_token', access_token)
          localStorage.setItem('refresh_token', refresh_token)

          // Fetch user info
          const userResponse = await api.get('/auth/me')
          set({ 
            user: userResponse.data, 
            isAuthenticated: true,
            isLoading: false 
          })

          toast.success('Login successful')
        } catch (error) {
          set({ isLoading: false })
          throw error
        }
      },

      logout: () => {
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        set({ user: null, isAuthenticated: false })
        toast.success('Logged out successfully')
      },

      fetchCurrentUser: async () => {
        try {
          const response = await api.get('/auth/me')
          set({ 
            user: response.data, 
            isAuthenticated: true 
          })
        } catch (error) {
          set({ user: null, isAuthenticated: false })
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ 
        user: state.user, 
        isAuthenticated: state.isAuthenticated 
      }),
    }
  )
)
```

---

## 📁 File 109: `frontend/src/App.tsx`

```
TypeScript
```

```
import { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './store/authStore'
import { wsClient } from './lib/websocket'

// Pages (will create these next)
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import Incidents from './pages/Incidents'
import Layout from './components/layout/Layout'

// Protected route wrapper
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function App() {
  const { isAuthenticated, fetchCurrentUser } = useAuthStore()

  useEffect(() => {
    // Check if user is already authenticated
    const token = localStorage.getItem('access_token')
    if (token) {
      fetchCurrentUser()
    }
  }, [fetchCurrentUser])

  useEffect(() => {
    // Connect WebSocket when authenticated
    if (isAuthenticated) {
      const token = localStorage.getItem('access_token')
      wsClient.connect(token || undefined)

      return () => {
        wsClient.disconnect()
      }
    }
  }, [isAuthenticated])

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="incidents" element={<Incidents />} />
        {/* More routes will be added */}
      </Route>
    </Routes>
  )
}

export default App
```

---

## 📁 File 110: `frontend/.env.example`

```
Bash
```

```
# API Configuration
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000

# App Configuration
VITE_APP_NAME=Advanced IDS
VITE_APP_VERSION=1.0.0
```

---

## 📁 File 111: `frontend/.gitignore`

```
text
```

```
# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*
lerna-debug.log*

node_modules
dist
dist-ssr
*.local

# Editor directories and files
.vscode/*
!.vscode/extensions.json
.idea
.DS_Store
*.suo
*.ntvs*
*.njsproj
*.sln
*.sw?

# Environment
.env
.env.local
.env.production
```

---

## 📁 File 112: `frontend/README.md`

```
Markdown
```

````
# Advanced IDS - Frontend

React + TypeScript frontend for the Advanced Intrusion Detection System.

## Tech Stack

- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Recharts** - Data visualization
- **Zustand** - State management
- **React Router** - Routing
- **Axios** - HTTP client
- **WebSocket** - Real-time updates

## Getting Started

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
````

## Project Structure

```
text
```

```
src/
├── components/      # Reusable components
│   ├── layout/     # Layout components
│   ├── common/     # Common UI components
│   └── dashboard/  # Dashboard-specific components
├── pages/          # Page components
├── lib/            # Utilities (API, WebSocket)
├── store/          # Zustand stores
├── types/          # TypeScript types
└── hooks/          # Custom React hooks
```

## Environment Variables

Copy **`.env.example`** to **`.env`** and configure:

```
Bash
```

```
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

## Development

The frontend connects to the backend API at **`http://localhost:8000`**.

Make sure the backend is running before starting the frontend.

## Features

- ✅ Authentication with JWT
- ✅ Real-time WebSocket updates
- ✅ Dark cybersecurity theme
- ✅ Responsive layout
- 🔄 Dashboard with live stats (in progress)
- 🔄 Alert management (in progress)
- 🔄 Incident investigation (in progress)

```
text
```

````

---

## ✅ PHASE 10 COMPLETE

**Implemented:**
- ✅ Complete project setup (Vite + React + TypeScript)
- ✅ Tailwind CSS with dark cybersecurity theme
- ✅ API client with axios (auth interceptors)
- ✅ WebSocket client (reconnection, event handling)
- ✅ Zustand auth store (login, logout, persistence)
- ✅ TypeScript types for all entities
- ✅ Routing structure
- ✅ Protected route wrapper
- ✅ Toast notifications
- ✅ Custom CSS utilities
- ✅ Environment configuration

**Setup Instructions:**

```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Create environment file
cp .env.example .env

# Start development server
npm run dev

# Frontend will run on http://localhost:3000
````

**Current Structure:**

```
text
```

```
frontend/
├── src/
│   ├── components/     (empty, will fill next)
│   ├── pages/          (empty, will fill next)
│   ├── lib/            ✅ API + WebSocket
│   ├── store/          ✅ Auth store
│   ├── types/          ✅ All types
│   ├── App.tsx         ✅ Main app with routing
│   ├── main.tsx        ✅ Entry point
│   └── index.css       ✅ Styles
├── package.json        ✅
├── vite.config.ts      ✅
├── tailwind.config.js  ✅
└── tsconfig.json       ✅
```

**Next Phase:** Build the actual UI components and pages!

**Ab kya banayein?**

Reply with:

- **"LOGIN"** - Build login page first
- **"DASHBOARD"** - Build main dashboard (recommended!)
- **"COMPONENTS"** - Build common components first

**Dashboard shuru karein?** 🎨