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
