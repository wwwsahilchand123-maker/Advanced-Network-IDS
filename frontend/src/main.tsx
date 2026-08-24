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
