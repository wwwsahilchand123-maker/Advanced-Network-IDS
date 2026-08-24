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
