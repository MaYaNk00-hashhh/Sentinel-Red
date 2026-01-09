import type { LoginCredentials, RegisterData, AuthResponse, User } from '@/types/auth'
import apiClient from '@/lib/api'

export const authService = {
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    const { data } = await apiClient.post<AuthResponse>('/auth/login', credentials)
    return data
  },

  async register(data: RegisterData): Promise<AuthResponse> {
    const { data: response } = await apiClient.post<AuthResponse>('/auth/register', data)
    return response
  },

  async forgotPassword(email: string): Promise<void> {
    await apiClient.post('/auth/forgot-password', { email })
  },

  async resetPassword(token: string, password: string): Promise<void> {
    await apiClient.post('/auth/reset-password', { token, password })
  },

  async getCurrentUser(): Promise<User> {
    const { data } = await apiClient.get<User>('/auth/me')
    return data
  },

  async logout(): Promise<void> {
    localStorage.removeItem('auth_token')
    localStorage.removeItem('refresh_token')
  },
}
