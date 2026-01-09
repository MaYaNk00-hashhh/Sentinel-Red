
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'
import { Button } from '@/components/ui/button'
import {
  LayoutDashboard,
  ShieldAlert,
  Scan,
  FileText,
  Settings,
  LogOut,
  Menu,
  X
} from 'lucide-react'
import { useState } from 'react'
import { cn } from '@/lib/utils'

const navItems = [
  { path: '/dashboard', icon: LayoutDashboard, label: 'Projects' },
  { path: '/dashboard/vulnerabilities', icon: ShieldAlert, label: 'Vulnerabilities' },
  { path: '/dashboard/scan/proj-1', icon: Scan, label: 'Scanning' },
  { path: '/dashboard/report/scan-1', icon: FileText, label: 'Reports' },
  { path: '/dashboard/settings', icon: Settings, label: 'Settings' },
]

export default function DashboardLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { user, clearAuth } = useAuthStore()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const handleLogout = () => {
    clearAuth()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed left-0 top-0 z-50 h-screen w-64 border-r border-yellow-green/30 bg-card backdrop-blur-sm transition-transform duration-300 lg:translate-x-0 shadow-xl shadow-yellow-green/10',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <div className="flex h-full flex-col">
          {/* Header */}
          <div className="flex h-16 items-center justify-between border-b border-yellow-green/30 px-6 bg-gradient-to-r from-yellow-green/10 to-transparent">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-lg bg-yellow-green flex items-center justify-center border-2 border-yellow-green shadow-lg shadow-yellow-green/50">
                <ShieldAlert className="h-5 w-5 text-background" />
              </div>
              <span className="font-black text-lg text-yellow-green">Sentinel Red</span>
            </div>
            <Button
              variant="ghost"
              size="icon"
              className="lg:hidden"
              onClick={() => setSidebarOpen(false)}
            >
              <X className="h-5 w-5" />
            </Button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 space-y-2 p-4">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              return (
                <button
                  key={item.path}
                  onClick={() => {
                    navigate(item.path)
                    setSidebarOpen(false)
                  }}
                  className={cn(
                    'w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-200',
                    isActive
                      ? 'bg-yellow-green/20 text-yellow-green border-2 border-yellow-green/50 shadow-lg shadow-yellow-green/20 font-bold'
                      : 'text-dim-grey-light hover:bg-yellow-green/10 hover:text-yellow-green hover:border hover:border-yellow-green/30'
                  )}
                >
                  <Icon className={cn('h-5 w-5', isActive ? 'text-red-400' : '')} />
                  {item.label}
                </button>
              )
            })}
          </nav>

          {/* User section */}
          <div className="border-t p-4">
            <div className="mb-3 px-4">
              <p className="text-sm font-medium">{user?.name}</p>
              <p className="text-xs text-muted-foreground">{user?.email}</p>
            </div>
            <Button
              variant="ghost"
              className="w-full justify-start gap-3"
              onClick={handleLogout}
            >
              <LogOut className="h-4 w-4" />
              Logout
            </Button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <header className="sticky top-0 z-30 h-16 border-b border-yellow-green/30 bg-gradient-to-r from-background/95 via-yellow-green/5 to-background/95 backdrop-blur-md supports-[backdrop-filter]:bg-background/80 shadow-sm shadow-yellow-green/10">
          <div className="flex h-full items-center justify-between px-6">
            <Button
              variant="ghost"
              size="icon"
              className="lg:hidden"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="h-5 w-5" />
            </Button>
            <div className="flex-1" />
            <div className="flex items-center gap-2">
              <span className="text-sm text-dim-grey-light">
                {user?.role === 'admin' && (
                  <span className="rounded-full bg-yellow-green/20 px-2 py-1 text-xs text-yellow-green font-bold border border-yellow-green/30">
                    Admin
                  </span>
                )}
              </span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
