import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './design-tokens.css'
import './index.css'
import './app.css'
import './ids.css'
import './soc-revamp.css'
import './rfuav-theme.css'
import './login.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
