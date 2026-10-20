const AUTH_KEY = 'sg_auth_session'

export type AuthSession = {
  user: string
  name: string
  role: string
  loggedInAt: string
}

const DEMO_USERS: Record<string, { password: string; name: string; role: string }> = {
  analyst: { password: 'cortes', name: 'SOC Analyst', role: 'ANALYST' },
  admin: { password: 'cortes', name: 'Security Admin', role: 'ADMIN' },
}

export function readSession(): AuthSession | null {
  try {
    const raw = localStorage.getItem(AUTH_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as AuthSession
    if (!parsed?.user) return null
    return parsed
  } catch {
    return null
  }
}

export function writeSession(session: AuthSession) {
  localStorage.setItem(AUTH_KEY, JSON.stringify(session))
}

export function clearSession() {
  localStorage.removeItem(AUTH_KEY)
}

export function authenticate(username: string, password: string): AuthSession | null {
  const key = username.trim().toLowerCase()
  const account = DEMO_USERS[key]
  if (!account || account.password !== password) return null
  return {
    user: key,
    name: account.name,
    role: account.role,
    loggedInAt: new Date().toISOString(),
  }
}
