/** Browser-persisted chat history — survives refresh even if Postgres is down. */

export type StoredChatMessage = {
  id: string
  role: 'user' | 'assistant'
  content?: string
  mode?: 'agentic' | 'dual'
  agent?: Record<string, unknown> | null
  original?: Record<string, unknown> | null
  docling?: Record<string, unknown> | null
}

export type LocalConversation = {
  id: string
  title: string
  updated_at: string
  document_filter?: string
  top_k?: number
  messages: StoredChatMessage[]
}

const STORE_KEY = 'sf_chats_v1'
const ACTIVE_KEY = 'sf_active_chat_id'

type StoreShape = {
  conversations: LocalConversation[]
}

function readStore(): StoreShape {
  try {
    const raw = localStorage.getItem(STORE_KEY)
    if (!raw) return { conversations: [] }
    const parsed = JSON.parse(raw) as StoreShape
    if (!parsed || !Array.isArray(parsed.conversations)) return { conversations: [] }
    return parsed
  } catch {
    return { conversations: [] }
  }
}

function writeStore(data: StoreShape) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(data))
  } catch {
    // Quota exceeded — drop oldest chats until it fits.
    const trimmed = { conversations: data.conversations.slice(0, 20) }
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(trimmed))
    } catch {
      /* ignore */
    }
  }
}

export function getActiveConversationId(): string | null {
  try {
    return localStorage.getItem(ACTIVE_KEY)
  } catch {
    return null
  }
}

export function setActiveConversationId(id: string | null) {
  try {
    if (id) localStorage.setItem(ACTIVE_KEY, id)
    else localStorage.removeItem(ACTIVE_KEY)
  } catch {
    /* ignore */
  }
}

export function listLocalConversations(): LocalConversation[] {
  return [...readStore().conversations].sort((a, b) =>
    (b.updated_at || '').localeCompare(a.updated_at || ''),
  )
}

export function getLocalConversation(id: string): LocalConversation | null {
  return readStore().conversations.find((c) => c.id === id) || null
}

export function upsertLocalConversation(conv: LocalConversation) {
  const store = readStore()
  const idx = store.conversations.findIndex((c) => c.id === conv.id)
  const next = { ...conv, updated_at: conv.updated_at || new Date().toISOString() }
  if (idx >= 0) store.conversations[idx] = next
  else store.conversations.unshift(next)
  // Keep last 40 chats
  store.conversations = store.conversations
    .sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''))
    .slice(0, 40)
  writeStore(store)
  setActiveConversationId(conv.id)
}

export function deleteLocalConversation(id: string) {
  const store = readStore()
  store.conversations = store.conversations.filter((c) => c.id !== id)
  writeStore(store)
  if (getActiveConversationId() === id) setActiveConversationId(null)
}

export function titleFromMessages(messages: { role: string; content?: string }[]): string {
  const first = messages.find((m) => m.role === 'user' && m.content?.trim())
  const t = (first?.content || 'New chat').trim().replace(/\s+/g, ' ')
  return t.length > 56 ? `${t.slice(0, 56)}…` : t
}
