export interface User {
  id: string
  email: string
  name: string
  role: 'admin' | 'user'
  created_at: string
}

export interface LoginCredentials {
  email: string
  password: string
}

export interface RegisterData {
  email: string
  password: string
  name: string
}

export interface AuthResponse {
  token: string
  access_token?: string
  refresh_token: string
  user: User
}
