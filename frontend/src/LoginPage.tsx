import { useState } from 'react'
import type { FormEvent } from 'react'
import { authenticate, writeSession, type AuthSession } from './auth'
import { IconShield } from './icons'
import CommandCenterBg from './CommandCenterBg'

type Props = {
  onSuccess: (session: AuthSession) => void
}

export default function LoginPage({ onSuccess }: Props) {
  const [username, setUsername] = useState('analyst')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [showPass, setShowPass] = useState(false)

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    window.setTimeout(() => {
      const session = authenticate(username, password)
      if (!session) {
        setError('Invalid credentials. Use analyst / cortes')
        setBusy(false)
        return
      }
      writeSession(session)
      onSuccess(session)
      setBusy(false)
    }, 420)
  }

  return (
    <div className="sg-login">
      <CommandCenterBg />
      <div className="sg-login__ambient" aria-hidden />
      <div className="sg-login__grid" aria-hidden />

      <aside className="sg-login__brand">
        <div className="sg-login__brand-inner">
          <div className="sg-login__mark">
            <IconShield />
          </div>
          <p className="sg-login__eyebrow">TELECOM INTERCONNECT SECURITY</p>
          <h1>CORTES</h1>
          <p className="sg-login__tag">Analyst</p>
          <p className="sg-login__lead">
            Secure access to the signaling firewall console for SS7, Diameter, and GTP-C interconnect monitoring.
          </p>
          <ul className="sg-login__bullets">
            <li>CAT1–CAT3 enforcement</li>
            <li>IR.21 partner validation</li>
            <li>Live threat intelligence</li>
          </ul>
        </div>
        <div className="sg-login__tower" aria-hidden>
          <svg viewBox="0 0 360 220" fill="none">
            <path d="M250 200 L290 40 L330 200" stroke="currentColor" strokeWidth="1.4" />
            <path d="M270 200 L290 70 L310 200" stroke="currentColor" strokeWidth="1.2" opacity="0.7" />
            <circle cx="290" cy="34" r="5" fill="currentColor" />
            <path d="M268 26 a28 28 0 0 1 44 0" stroke="currentColor" strokeWidth="1.2" opacity="0.8" />
            <path d="M250 14 a48 48 0 0 1 80 0" stroke="currentColor" strokeWidth="1" strokeDasharray="4 3" opacity="0.45" />
            <path d="M30 170 C90 130 140 160 190 100 C230 60 270 90 340 50" stroke="currentColor" strokeWidth="1" opacity="0.35" />
            <circle cx="90" cy="140" r="2.2" fill="currentColor" opacity="0.7" />
            <circle cx="160" cy="128" r="2.2" fill="currentColor" opacity="0.55" />
            <circle cx="220" cy="88" r="2.2" fill="currentColor" opacity="0.45" />
          </svg>
        </div>
      </aside>

      <main className="sg-login__panel">
        <form className="sg-login__card" onSubmit={onSubmit}>
          <div className="sg-login__card-head">
            <span className="sg-login__live">
              <span className="sg-login__live-dot" />
              SECURE GATEWAY
            </span>
            <h2>Sign in</h2>
            <p>Enter your SOC credentials to open the operations console.</p>
          </div>

          <label className="sg-login__field">
            <span>Username</span>
            <input
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="analyst"
              required
            />
          </label>

          <label className="sg-login__field">
            <span>Password</span>
            <div className="sg-login__pass">
              <input
                type={showPass ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
              <button type="button" onClick={() => setShowPass((v) => !v)}>
                {showPass ? 'Hide' : 'Show'}
              </button>
            </div>
          </label>

          {error ? <p className="sg-login__error">{error}</p> : null}

          <button type="submit" className="sg-login__submit" disabled={busy}>
            {busy ? 'Authenticating…' : 'Enter Console'}
          </button>

          <p className="sg-login__hint">
            Demo access · <code>analyst</code> / <code>cortes</code>
          </p>
        </form>
      </main>
    </div>
  )
}
