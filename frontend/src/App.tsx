import { useEffect, useRef, useState } from 'react'
import type { FormEvent, MouseEvent, ReactNode } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import IDSDashboard from './IDSDashboard'
import {
  IconAllow,
  IconBell,
  IconChat,
  IconHome,
  IconInspect,
  IconLibrary,
  IconMenu,
  IconPlus,
  IconPulse,
  IconRefresh,
  IconSearch,
  IconSend,
  IconLogout,
  IconStop,
  IconShield,
  IconSpark,
  IconUpload,
  IconWarn,
} from './icons'
import LoginPage from './LoginPage'
import CommandCenterBg from './CommandCenterBg'
import { clearSession, readSession, type AuthSession } from './auth'
import { formatRelative, nowClock } from './lib/format'
import {
  fetchConversation,
  fetchConversations,
  fetchStatus,
  fetchStructure,
  clearEnrollment,
  deleteConversation,
  indexFiles,
  indexSample,
  refreshAllData,
  refreshEmbeddings,
  refreshStructured,
  streamChat,
  type ChunkHit,
  type ConversationSummary,
  type PipelineResult,
  type StatusResponse,
  type StoredMessage,
} from './api'
import {
  deleteLocalConversation,
  getActiveConversationId,
  getLocalConversation,
  listLocalConversations,
  setActiveConversationId,
  titleFromMessages,
  upsertLocalConversation,
  type LocalConversation,
  type StoredChatMessage,
} from './chatStore'
import { randomId } from './uuid'

type Tab = 'dashboard' | 'chat' | 'index' | 'structure'
type DashFocus = 'overview' | 'traffic' | 'alerts' | 'partners' | 'rules' | 'threats' | 'analytics'

type ChatMessage = {
  id: string
  role: 'user' | 'assistant'
  content?: string
  status?: string
  mode?: 'agentic' | 'dual'
  streaming?: boolean
  agent?: PipelineResult | null
  original?: PipelineResult | null
  docling?: PipelineResult | null
}

function cleanFileName(name?: string | null) {
  if (!name) return ''
  return name.replace(/^[a-f0-9]{24,}_?/i, '').replace(/\.pdf$/i, '')
}

function detectFsDoc(chunk: ChunkHit): string | null {
  if (chunk.fs_doc) return chunk.fs_doc
  const blob = `${chunk.file_name || ''} ${chunk.section || ''} ${chunk.preview || ''}`
  const m = blob.match(/\bFS\.(11|19|20|21)\b/i)
  return m ? `FS.${m[1]}` : null
}

function EvidencePanel({ chunks }: { chunks: ChunkHit[] }) {
  if (!chunks?.length) {
    return <div className="chunks-empty">No retrieved chunk details available.</div>
  }
  const ranked = [...chunks].sort((a, b) => (b.score || 0) - (a.score || 0))
  return (
    <div className="chunks">
      {ranked.map((c) => {
        const fs = detectFsDoc(c)
        return (
          <div className={`chunk${fs ? ` fs-${fs.replace('.', '').toLowerCase()}` : ''}`} key={`${c.chunk_id}-${c.rank}`}>
            <div className="chunk-head">
              <strong>
                #{c.rank} [{c.content_type}]
              </strong>
              <span className="chunk-score" title="Retrieval relevance score">
                score {Number(c.score || 0).toFixed(3)}
              </span>
              {fs ? <span className="fs-badge">{fs}</span> : null}
              <span>
                {c.page != null ? `p.${c.page}` : ''}
                {c.section ? ` · ${c.section}` : ''}
                {c.file_name ? ` · ${cleanFileName(c.file_name)}` : ''}
              </span>
            </div>
            <div className="chunk-preview">{c.preview}</div>
          </div>
        )
      })}
    </div>
  )
}

function fsHitsSummary(chunks?: ChunkHit[] | null): string {
  if (!chunks?.length) return ''
  const counts: Record<string, number> = {}
  for (const c of chunks) {
    const fs = detectFsDoc(c)
    if (fs) counts[fs] = (counts[fs] || 0) + 1
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `${k}×${v}`)
    .join(' · ')
}

function PipelineCard({
  kind,
  data,
  pending,
}: {
  kind: 'original' | 'docling' | 'agentic'
  data?: PipelineResult | null
  pending?: string
}) {
  const [chunksOpen, setChunksOpen] = useState(false)
  const chunksRef = useRef<HTMLDivElement>(null)
  const tag =
    kind === 'original' ? 'ORIGINAL' : kind === 'docling' ? 'DOCLING · HYBRID' : 'AGENTIC RAG'
  const hasChunks = Boolean(data?.chunks?.length)
  const canToggleChunks = Boolean(data && (hasChunks || (data.hits ?? 0) > 0))
  const fsSummary = fsHitsSummary(data?.chunks)
  const domain =
    data?.knowledge_domain ||
    (typeof data?.agent_context?._knowledge_domain === 'string'
      ? data.agent_context._knowledge_domain
      : undefined)

  useEffect(() => {
    if (chunksOpen && chunksRef.current) {
      chunksRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }
  }, [chunksOpen])

  return (
    <div className={`pipeline-card ${kind}${chunksOpen ? ' chunks-expanded' : ''}`}>
      <div className="pipeline-body">
        {data?.answer?.trim() ? (
          <div className="md answer-md">
            <Markdown
              remarkPlugins={[remarkGfm]}
              components={markdownComponents}
            >
              {data.answer}
            </Markdown>
          </div>
        ) : data ? (
          <div className="pending">No answer text was returned.</div>
        ) : (
          <div className="gpt-typing" aria-label={pending || 'Thinking'}>
            <span />
            <span />
            <span />
          </div>
        )}
        {data?.finding?.finding &&
        (data.finding.severity === 'high' ||
          data.finding.severity === 'medium' ||
          data.query_type === 'SECURITY_INVESTIGATION') ? (
          <p className="brand-sub" style={{ marginTop: '0.75rem', opacity: 0.85 }}>
            {data.finding.severity ? `${data.finding.severity} · ` : ''}
            {data.finding.finding}
            {data.finding.recommendation ? ` — ${data.finding.recommendation}` : ''}
          </p>
        ) : null}
        {data?.reports?.length ? (
          <p className="brand-sub" style={{ marginTop: '0.4rem', opacity: 0.7, fontSize: '0.8rem' }}>
            Specialists:{' '}
            {data.reports
              .filter((r) => (r.hits || 0) > 0)
              .slice(0, 6)
              .map((r) => `${r.agent}→${r.store} (${r.hits})`)
              .join(' · ')}
          </p>
        ) : null}
        {data?.round1_documents?.length ? (
          <p className="brand-sub" style={{ marginTop: '0.35rem', opacity: 0.65, fontSize: '0.75rem' }}>
            Round-1 docs:{' '}
            {data.round1_documents
              .slice(0, 4)
              .map((d) => cleanFileName(d.file_name) || d.source || '?')
              .join(' · ')}
          </p>
        ) : null}
        {data?.detection_rules?.length &&
        (data.query_type === 'SECURITY_INVESTIGATION' ||
          /rule|detection|suricata|ids/i.test(data.answer || '')) ? (
          <ul className="brand-sub" style={{ marginTop: '0.4rem', opacity: 0.8, fontSize: '0.8rem' }}>
            {data.detection_rules.slice(0, 3).map((r, i) => (
              <li key={i}>
                {r.grounded && r.rule
                  ? `${r.sid ? `sid:${r.sid} ` : ''}${r.rule}${r.source ? ` (${r.source})` : ''}`
                  : r.note || r.rule}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
      {data && (
        <div className="pipeline-head">
          {canToggleChunks ? (
            <button
              type="button"
              className={`hits-link${chunksOpen ? ' active' : ''}`}
              onClick={() => setChunksOpen((v) => !v)}
              aria-expanded={chunksOpen}
              title={chunksOpen ? 'Hide sources' : 'Show sources'}
            >
              Sources{typeof data.hits === 'number' ? ` · ${data.hits}` : ''}
            </button>
          ) : (
            <span className="tag">{tag}</span>
          )}
          <span className="meta">
            {data.ms ? `${data.ms}ms` : ''}
            {fsSummary ? ` · ${fsSummary}` : ''}
            {domain ? ` · ${domain}` : ''}
            {pending === 'streaming…' ? ' · streaming' : ''}
          </span>
        </div>
      )}
      {data && chunksOpen && (
        <div className="chunks-panel" ref={chunksRef}>
          <div className="chunks-panel-label">
            Ranked evidence ({data.chunks?.length ?? data.hits})
            {fsSummary ? ` · ${fsSummary}` : ''}
          </div>
          <EvidencePanel chunks={data.chunks || []} />
        </div>
      )}
    </div>
  )
}

function storedToChatMessages(rows: StoredMessage[]): ChatMessage[] {
  const out: ChatMessage[] = []
  for (const row of rows) {
    if (row.role === 'user') {
      out.push({ id: row.id, role: 'user', content: row.content || '' })
      continue
    }
    const meta = row.metadata || {}
    if (meta.mode === 'agentic' && meta.agent) {
      out.push({ id: row.id, role: 'assistant', mode: 'agentic', agent: meta.agent })
    } else if (meta.original && meta.docling) {
      out.push({
        id: row.id,
        role: 'assistant',
        mode: 'dual',
        original: meta.original,
        docling: meta.docling,
      })
    } else if (row.content) {
      out.push({
        id: row.id,
        role: 'assistant',
        mode: 'agentic',
        agent: {
          pipeline: 'agentic',
          answer: row.content,
          ms: 0,
          hits: 0,
          sources: [],
          chunks: [],
        },
      })
    }
  }
  return out
}

function localToChatMessages(rows: StoredChatMessage[]): ChatMessage[] {
  return rows.map((row) => ({
    id: row.id,
    role: row.role,
    content: row.content,
    mode: row.mode,
    agent: (row.agent as PipelineResult | null | undefined) ?? undefined,
    original: (row.original as PipelineResult | null | undefined) ?? undefined,
    docling: (row.docling as PipelineResult | null | undefined) ?? undefined,
  }))
}

function chatToStored(messages: ChatMessage[]): StoredChatMessage[] {
  return messages
    .filter((m) => !m.streaming)
    .map((m) => ({
      id: m.id,
      role: m.role,
      content: m.content,
      mode: m.mode,
      agent: m.agent ? (m.agent as unknown as Record<string, unknown>) : null,
      original: m.original ? (m.original as unknown as Record<string, unknown>) : null,
      docling: m.docling ? (m.docling as unknown as Record<string, unknown>) : null,
    }))
}

function mergeConversationLists(
  api: ConversationSummary[],
  local: LocalConversation[],
): ConversationSummary[] {
  const map = new Map<string, ConversationSummary>()
  for (const c of local) {
    map.set(c.id, {
      id: c.id,
      title: c.title,
      first_message: c.title,
      updated_at: c.updated_at,
      document_filter: c.document_filter,
      top_k: c.top_k,
    })
  }
  for (const c of api) {
    const prev = map.get(c.id)
    map.set(c.id, {
      ...c,
      title: c.title || c.first_message || prev?.title || 'Chat',
      first_message: c.first_message || prev?.first_message,
      updated_at: c.updated_at || prev?.updated_at,
    })
  }
  return [...map.values()].sort((a, b) =>
    String(b.updated_at || '').localeCompare(String(a.updated_at || '')),
  )
}

function Logo() {
  return (
    <div className="ss7-logo ss7-logo--rail">
      <div className="ss7-logo__icon">
        <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="logo-gradient" x1="4" y1="4" x2="36" y2="36">
              <stop offset="0%" stopColor="#8AEBFF" />
              <stop offset="100%" stopColor="#22D3EE" />
            </linearGradient>
          </defs>
          <path
            d="M20 4.5 7.8 9.6v8.1c0 7.1 4.9 13.4 12.2 15.1 7.3-1.7 12.2-8 12.2-15.1V9.6L20 4.5Z"
            stroke="url(#logo-gradient)"
            strokeWidth="1.8"
          />
          <path d="M14 20.4 18.1 24.4 26.2 15.6" stroke="#22D3EE" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      <div className="ss7-logo__text">
        <span className="ss7-logo__name">CORTES</span>
        <span className="ss7-logo__tagline">Analyst</span>
      </div>
    </div>
  )
}

type MethodId = 'retrieval' | 'rule_gen' | 'blocking' | 'cat1' | 'cat2' | 'cat3' | 'explanation'

type MethodItem = {
  id: MethodId
  label: string
  blurb: string
  chatCase: 'case1' | 'case2' | 'case3'
  prompt: string
  icon: ReactNode
}

const METHODOLOGY: MethodItem[] = [
  {
    id: 'retrieval',
    label: 'Retrieval',
    blurb: 'Standards + IR.21 RAG',
    chatCase: 'case2',
    icon: <IconSearch />,
    prompt:
      'Explain the CORTES retrieval methodology: how GSMA FS specs, 3GPP references, and IR.21 partner facts are retrieved, ranked, and grounded before answering a signaling question.',
  },
  {
    id: 'rule_gen',
    label: 'Rule Generation',
    blurb: 'Suricata / policy draft',
    chatCase: 'case3',
    icon: <IconInspect />,
    prompt:
      'Explain the CORTES rule-generation methodology: how CAT policy intent is translated into enforceable Suricata/signaling firewall rules with SID, match conditions, and action.',
  },
  {
    id: 'blocking',
    label: 'Blocking',
    blurb: 'Deny / drop decisions',
    chatCase: 'case1',
    icon: <IconShield />,
    prompt:
      'Explain the CORTES blocking methodology: when interconnect traffic is denied, how evidence is collected from live IDS, and how ALLOW / BLOCK / ESCALATE decisions are justified.',
  },
  {
    id: 'cat1',
    label: 'CAT 1',
    blurb: 'Critical block path',
    chatCase: 'case1',
    icon: <IconWarn />,
    prompt:
      'Explain Category-1 (CAT1) methodology in CORTES: which signaling messages are prohibited on interconnect, why they are blocked immediately, and how detection maps to enforcement.',
  },
  {
    id: 'cat2',
    label: 'CAT 2',
    blurb: 'Validate & filter',
    chatCase: 'case2',
    icon: <IconAllow />,
    prompt:
      'Explain Category-2 (CAT2) methodology in CORTES: partner/realm validation, IR.21 checks, and when traffic is filtered versus passed after verification.',
  },
  {
    id: 'cat3',
    label: 'CAT 3',
    blurb: 'Escalate & monitor',
    chatCase: 'case3',
    icon: <IconPulse />,
    prompt:
      'Explain Category-3 (CAT3 / 3.1 / 3.2) methodology in CORTES: which events escalate for analyst review, how monitoring differs from hard block, and escalation criteria.',
  },
  {
    id: 'explanation',
    label: 'Explanation',
    blurb: 'Decision rationale',
    chatCase: 'case2',
    icon: <IconLibrary />,
    prompt:
      'Explain the CORTES explanation methodology: how answers cite retrieved standards, map to CAT policy, show rule evidence, and produce an analyst-ready rationale for a decision.',
  },
]

function NavItem({
  icon,
  label,
  active,
  badge,
  title,
  onClick,
}: {
  icon: ReactNode
  label: string
  active: boolean
  badge?: number | string
  title?: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      className={`ss7-nav__item ss7-rail__item ${active ? 'ss7-nav__item--active ss7-rail__item--active' : ''}`}
      onClick={onClick}
      title={title || label}
    >
      <span className="ss7-nav__icon ss7-rail__icon">{icon}</span>
      <span className="ss7-nav__label ss7-rail__label">{label}</span>
      {badge !== undefined && badge !== 0 && badge !== '' && (
        <span className="ss7-nav__badge ss7-rail__badge">{badge}</span>
      )}
    </button>
  )
}

const markdownComponents = {
  table: ({ children }: { children?: ReactNode }) => (
    <div className="table-wrap">
      <table>{children}</table>
    </div>
  ),
  pre: ({ children }: { children?: ReactNode }) => <pre className="sg-code-block">{children}</pre>,
  code: ({ className, children, ...props }: { className?: string; children?: ReactNode }) => {
    const isBlock = typeof className === 'string' && className.includes('language-')
    if (isBlock) {
      return (
        <code className={`sg-code-block__code ${className}`} {...props}>
          {children}
        </code>
      )
    }
    return (
      <code className="sg-code-inline" {...props}>
        {children}
      </code>
    )
  },
}

export default function App() {
  const [session, setSession] = useState<AuthSession | null>(() => readSession())
  const [tab, setTab] = useState<Tab>('chat')
  const [dashFocus, setDashFocus] = useState<DashFocus>('overview')
  const [chatCase, setChatCase] = useState<'case1' | 'case2' | 'case3'>('case1')
  const [status, setStatus] = useState<StatusResponse | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [clock, setClock] = useState(() => nowClock())
  const [headerSearch, setHeaderSearch] = useState('')
  const [topK, setTopK] = useState(8)
  const [document, setDocument] = useState('All documents')
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [conversations, setConversations] = useState<ConversationSummary[]>([])
  const [conversationId, setConversationId] = useState<string | null>(null)
  const [chatHistoryQuery, setChatHistoryQuery] = useState('')
  const [activeMethod, setActiveMethod] = useState<MethodId | null>(null)
  const [busy, setBusy] = useState(false)
  const [apiError, setApiError] = useState<string | null>(null)
  const [indexLog, setIndexLog] = useState('')
  const [indexBusy, setIndexBusy] = useState(false)
  const [enrollmentMode, setEnrollmentMode] = useState<'structured' | 'vector'>('structured')
  const [structureDocs, setStructureDocs] = useState<string[]>([])
  const [structureSelected, setStructureSelected] = useState('')
  const [structureReport, setStructureReport] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const abortRef = useRef<AbortController | null>(null)
  const conversationIdRef = useRef<string | null>(null)
  const hydratedRef = useRef(false)

  function persistChat(cid: string | null, msgs: ChatMessage[]) {
    if (!cid || !msgs.length) return
    const stored = chatToStored(msgs)
    if (!stored.some((m) => m.role === 'user')) return
    upsertLocalConversation({
      id: cid,
      title: titleFromMessages(stored),
      updated_at: new Date().toISOString(),
      document_filter: document === 'All documents' ? undefined : document,
      top_k: topK,
      messages: stored,
    })
    setConversations((list) => {
      const title = titleFromMessages(stored)
      const rest = list.filter((c) => c.id !== cid)
      return [
        {
          id: cid,
          title,
          first_message: title,
          updated_at: new Date().toISOString(),
          document_filter: document === 'All documents' ? undefined : document,
          top_k: topK,
        },
        ...rest,
      ]
    })
  }

  async function refreshStatus() {
    const s = await fetchStatus()
    setStatus(s)
    setTopK(Math.max(s.top_k_default || 8, 8))
    setApiError(null)
  }

  async function refreshConversationList() {
    const local = listLocalConversations()
    let api: ConversationSummary[] = []
    try {
      api = await fetchConversations()
    } catch {
      api = []
    }
    setConversations(mergeConversationLists(api, local))
  }

  useEffect(() => {
    conversationIdRef.current = conversationId
    setActiveConversationId(conversationId)
  }, [conversationId])

  useEffect(() => {
    const id = window.setInterval(() => setClock(nowClock()), 1000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    refreshStatus().catch((e) => {
      console.error(e)
      setApiError(
        `Cannot reach API at ${window.location.origin}/api/status — ${String(e)}. Open http://127.0.0.1:8000 in a system browser and hard-refresh.`,
      )
    })

    ;(async () => {
      await refreshConversationList()
      const active = getActiveConversationId()
      if (active && !hydratedRef.current) {
        hydratedRef.current = true
        try {
          await loadConversation(active)
        } catch {
          const local = getLocalConversation(active)
          if (local) {
            setConversationId(local.id)
            setMessages(localToChatMessages(local.messages || []))
            if (local.document_filter) setDocument(local.document_filter)
            if (local.top_k) setTopK(local.top_k)
          }
        }
      } else {
        hydratedRef.current = true
      }
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Persist after streaming finishes (messages settle).
  useEffect(() => {
    if (busy) return
    if (!conversationId || messages.length === 0) return
    persistChat(conversationId, messages)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [busy, conversationId, messages])

  async function loadConversation(id: string) {
    try {
      const data = await fetchConversation(id)
      if (data.messages?.length) {
        setConversationId(id)
        setMessages(storedToChatMessages(data.messages || []))
        if (data.conversation?.document_filter) setDocument(data.conversation.document_filter)
        if (data.conversation?.top_k) setTopK(data.conversation.top_k)
        setTab('chat')
        setSidebarOpen(false)
        setActiveConversationId(id)
        return
      }
    } catch {
      /* fall through to local */
    }
    const local = getLocalConversation(id)
    if (local) {
      setConversationId(id)
      setMessages(localToChatMessages(local.messages || []))
      if (local.document_filter) setDocument(local.document_filter)
      if (local.top_k) setTopK(local.top_k)
      setTab('chat')
      setSidebarOpen(false)
      setActiveConversationId(id)
      return
    }
    throw new Error('Chat not found')
  }

  async function startNewChat() {
    setConversationId(null)
    setActiveConversationId(null)
    setMessages([])
    setInput('')
    setActiveMethod(null)
    setTab('chat')
    setSidebarOpen(false)
  }

  function applyMethodology(method: MethodItem) {
    setActiveMethod(method.id)
    setChatCase(method.chatCase)
    setTab('chat')
    setSidebarOpen(false)
    void onSend(undefined, method.prompt)
  }

  async function onDeleteChat(id: string, e: MouseEvent) {
    e.stopPropagation()
    if (!window.confirm('Delete this chat?')) return
    deleteLocalConversation(id)
    try {
      await deleteConversation(id)
    } catch {
      /* local already removed */
    }
    setConversations((list) => list.filter((c) => c.id !== id))
    if (conversationId === id) {
      setConversationId(null)
      setActiveConversationId(null)
      setMessages([])
    }
  }

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 180
    if (nearBottom || busy) {
      el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' })
    }
  }, [messages, busy])

  async function loadStructure(doc?: string) {
    const data = await fetchStructure(doc)
    setStructureDocs(data.documents || [])
    setStructureSelected(data.selected || '')
    setStructureReport(data.report || data.error || 'No structure available.')
  }

  useEffect(() => {
    if (tab === 'structure') loadStructure().catch((e) => setStructureReport(String(e)))
  }, [tab])

  function resizeComposer(el?: HTMLTextAreaElement | null) {
    const node = el || inputRef.current
    if (!node) return
    node.style.height = 'auto'
    node.style.height = `${Math.min(node.scrollHeight, 200)}px`
  }

  function onStop() {
    abortRef.current?.abort()
    setBusy(false)
    setMessages((m) =>
      m.map((msg) => (msg.streaming ? { ...msg, streaming: false, status: undefined } : msg)),
    )
  }

  async function onSend(e?: FormEvent, preset?: string) {
    e?.preventDefault()
    const text = (preset ?? input).trim()
    if (!text || busy) return
    setInput('')
    if (inputRef.current) inputRef.current.style.height = 'auto'
    setBusy(true)
    const id = randomId()
    const agenticMode = status?.agentic_rag !== false
    setMessages((m) => [
      ...m,
      { id: id + '-u', role: 'user', content: text },
      {
        id,
        role: 'assistant',
        status: agenticMode ? 'Retrieving…' : 'Waiting for retrieval…',
        mode: agenticMode ? 'agentic' : 'dual',
        agent: agenticMode ? null : undefined,
        original: agenticMode ? undefined : null,
        docling: agenticMode ? undefined : null,
      },
    ])

    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac

    try {
      await streamChat(
        text,
        topK,
        document,
        {
          onStatus: (t) =>
            setMessages((m) => m.map((msg) => (msg.id === id ? { ...msg, status: t } : msg))),
          onToken: (tok) =>
            setMessages((m) =>
              m.map((msg) => {
                if (msg.id !== id) return msg
                const prev = msg.agent?.answer || ''
                return {
                  ...msg,
                  mode: 'agentic',
                  streaming: true,
                  status: undefined,
                  agent: {
                    pipeline: 'agentic',
                    answer: prev + tok,
                    ms: msg.agent?.ms ?? 0,
                    hits: msg.agent?.hits ?? 0,
                    sources: msg.agent?.sources ?? [],
                    chunks: msg.agent?.chunks ?? [],
                    tools_used: msg.agent?.tools_used,
                    query_type: msg.agent?.query_type,
                    confidence: msg.agent?.confidence,
                  },
                }
              }),
            ),
          onTokenReset: () =>
            setMessages((m) =>
              m.map((msg) => {
                if (msg.id !== id) return msg
                return {
                  ...msg,
                  mode: 'agentic',
                  streaming: true,
                  status: undefined,
                  agent: {
                    pipeline: 'agentic',
                    answer: '',
                    ms: msg.agent?.ms ?? 0,
                    hits: msg.agent?.hits ?? 0,
                    sources: msg.agent?.sources ?? [],
                    chunks: msg.agent?.chunks ?? [],
                    tools_used: msg.agent?.tools_used,
                    query_type: msg.agent?.query_type,
                    confidence: msg.agent?.confidence,
                  },
                }
              }),
            ),
          onAgent: (data) =>
            setMessages((m) =>
              m.map((msg) =>
                msg.id === id
                  ? { ...msg, mode: 'agentic', agent: data, streaming: false, status: undefined }
                  : msg,
              ),
            ),
          onOriginal: (data) =>
            setMessages((m) =>
              m.map((msg) =>
                msg.id === id
                  ? { ...msg, mode: 'dual', original: data, status: 'Generating DOCLING (hybrid)…' }
                  : msg,
              ),
            ),
          onDocling: (data) =>
            setMessages((m) =>
              m.map((msg) => (msg.id === id ? { ...msg, mode: 'dual', docling: data, status: undefined } : msg)),
            ),
          onConversationId: (cid) => {
            setConversationId(cid)
            conversationIdRef.current = cid
            setActiveConversationId(cid)
            refreshConversationList().catch(() => {})
          },
          onDone: () => setBusy(false),
          onError: (err) => {
            setMessages((m) =>
              m.map((msg) =>
                msg.id === id ? { ...msg, status: undefined, streaming: false, content: `Error: ${err}` } : msg,
              ),
            )
            setBusy(false)
          },
        },
        ac.signal,
        conversationId,
      )
    } catch (err) {
      if ((err as Error).name !== 'AbortError') {
        setMessages((m) =>
          m.map((msg) =>
            msg.id === id ? { ...msg, status: undefined, content: `Error: ${String(err)}` } : msg,
          ),
        )
      }
    } finally {
      setBusy(false)
    }
  }

  async function onIndex(files: FileList | null, targetPipelines: string[], modeLabel: string) {
    if (!files?.length) return
    setIndexBusy(true)
    setIndexLog(`Indexing (${modeLabel})…`)
    try {
      const res = await indexFiles(files, targetPipelines)
      setIndexLog(formatIndexResult(res))
      await refreshStatus()
    } catch (e) {
      setIndexLog(String(e))
    } finally {
      setIndexBusy(false)
    }
  }

  async function onSample(targetPipelines: string[], modeLabel: string) {
    setIndexBusy(true)
    setIndexLog(`Indexing sample (${modeLabel})…`)
    try {
      const res = await indexSample(targetPipelines)
      setIndexLog(formatIndexResult(res))
      await refreshStatus()
    } catch (e) {
      setIndexLog(String(e))
    } finally {
      setIndexBusy(false)
    }
  }

  function formatIndexResult(res: {
    indexed?: Array<{ file?: string; results?: Array<{ pipeline: string; ok: boolean; chunks?: number; error?: string }> }>
    results?: Array<{ pipeline: string; ok: boolean; chunks?: number; error?: string }>
    file?: string
  }): string {
    const lines: string[] = []
    const entries = res.indexed || (res.results ? [{ file: res.file, results: res.results }] : [])
    for (const item of entries) {
      lines.push(`\n## ${item.file || 'document'}`)
      for (const r of item.results || []) {
        if (r.ok) {
          const label =
            r.pipeline === 'docling'
              ? 'Structured (facts, tables, graph + vectors)'
              : 'Embeddings only (vectors)'
          lines.push(`✓ ${label}: ${r.chunks} chunks indexed`)
        } else {
          lines.push(`✗ ${r.pipeline}: ${r.error}`)
        }
      }
    }
    return lines.join('\n') || JSON.stringify(res, null, 2)
  }

  async function onRefreshStructured() {
    setIndexBusy(true)
    setIndexLog('Refreshing structured database…')
    try {
      const res = await refreshStructured()
      setIndexLog(res.message || JSON.stringify(res, null, 2))
    } catch (e) {
      setIndexLog(String(e))
    } finally {
      setIndexBusy(false)
    }
  }

  async function onRefreshEmbeddings() {
    setIndexBusy(true)
    setIndexLog('Syncing embeddings to Qdrant (original + docling)…')
    try {
      const res = await refreshEmbeddings('both')
      setIndexLog(res.message || JSON.stringify(res, null, 2))
    } catch (e) {
      setIndexLog(String(e))
    } finally {
      setIndexBusy(false)
    }
  }

  async function onClearEnrollment() {
    if (!window.confirm('Clear all enrolled documents (vectors + structured)? Platform seed data is kept.')) {
      return
    }
    setIndexBusy(true)
    setIndexLog('Clearing all enrollment…')
    try {
      const res = await clearEnrollment()
      setIndexLog(res.message || JSON.stringify(res, null, 2))
      await refreshStatus()
    } catch (e) {
      setIndexLog(String(e))
    } finally {
      setIndexBusy(false)
    }
  }

  async function onRefreshAll() {
    setIndexBusy(true)
    setIndexLog('Refreshing structured DB + embeddings…')
    try {
      const res = await refreshAllData()
      setIndexLog(JSON.stringify(res, null, 2))
      await refreshStatus()
    } catch (e) {
      setIndexLog(String(e))
    } finally {
      setIndexBusy(false)
    }
  }

  function onLogout() {
    clearSession()
    setSession(null)
    setSidebarOpen(false)
  }

  if (!session) {
    return <LoginPage onSuccess={setSession} />
  }

  const activeTitle =
    conversations.find((c) => c.id === conversationId)?.title ||
    (messages.length ? titleFromMessages(messages) : 'New chat')

  const filteredConversations = conversations.filter((c) => {
    const q = chatHistoryQuery.trim().toLowerCase()
    if (!q) return true
    const hay = `${c.title || ''} ${c.first_message || ''}`.toLowerCase()
    return hay.includes(q)
  })

  const historyGroups = (() => {
    const now = new Date()
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime()
    const startOfYesterday = startOfToday - 86400000
    const weekAgo = startOfToday - 7 * 86400000
    const buckets: { label: string; items: ConversationSummary[] }[] = [
      { label: 'Today', items: [] },
      { label: 'Yesterday', items: [] },
      { label: 'Previous 7 days', items: [] },
      { label: 'Older', items: [] },
    ]
    for (const c of filteredConversations) {
      const t = c.updated_at ? new Date(c.updated_at).getTime() : 0
      if (t >= startOfToday) buckets[0].items.push(c)
      else if (t >= startOfYesterday) buckets[1].items.push(c)
      else if (t >= weekAgo) buckets[2].items.push(c)
      else buckets[3].items.push(c)
    }
    return buckets.filter((b) => b.items.length > 0)
  })()

  const getPageTitle = () => {
    const dashTitles: Record<DashFocus, string> = {
      overview: 'Operations',
      traffic: 'Live Traffic',
      alerts: 'Alerts',
      partners: 'IR.21 Partners',
      rules: 'Rules & Policies',
      threats: 'Dashboard',
      analytics: 'Analytics',
    }
    switch (tab) {
      case 'dashboard': return dashTitles[dashFocus]
      case 'chat': return activeTitle
      case 'index': return 'Knowledge Base'
      case 'structure': return 'Document Explorer'
      default: return 'CORTES'
    }
  }

  return (
    <div className={`ss7-app ss7-app--rfuav${tab === 'chat' ? ' ss7-app--chat' : ''}`}>
      <CommandCenterBg />
      <div className="ss7-ambient ss7-ambient--live" aria-hidden="true" />
      <aside className={`ss7-sidebar ss7-rail ss7-rail--sc ${sidebarOpen ? 'ss7-sidebar--open ss7-rail--open' : ''}`}>
        <div className="ss7-rail__brand">
          <Logo />
          <span className={`ss7-rail__status${status ? ' is-on' : ''}`}>
            <span className="ss7-rail__status-dot" />
            {status ? 'CONNECTED' : 'OFFLINE'}
          </span>
        </div>

        <nav className="ss7-nav ss7-rail__nav">
          <div className="ss7-nav__section">
            <p className="ss7-nav__section-title">Main</p>
            <NavItem
              icon={<IconHome />}
              label="Dashboard"
              active={tab === 'dashboard' && (dashFocus === 'threats' || dashFocus === 'alerts' || dashFocus === 'overview' || dashFocus === 'analytics')}
              onClick={() => { setTab('dashboard'); setDashFocus('threats'); setSidebarOpen(false); }}
            />
            <NavItem
              icon={<IconChat />}
              label="Chat"
              active={tab === 'chat'}
              badge={conversations.length || undefined}
              onClick={() => { setTab('chat'); setSidebarOpen(false); }}
            />
          </div>

          <div className="ss7-nav__section">
            <p className="ss7-nav__section-title">Detection</p>
            <NavItem
              icon={<IconPulse />}
              label="Live Traffic"
              active={tab === 'dashboard' && dashFocus === 'traffic'}
              onClick={() => { setTab('dashboard'); setDashFocus('traffic'); setSidebarOpen(false); }}
            />
            <NavItem
              icon={<IconInspect />}
              label="Rules"
              active={tab === 'dashboard' && dashFocus === 'rules'}
              onClick={() => { setTab('dashboard'); setDashFocus('rules'); setSidebarOpen(false); }}
            />
            <NavItem
              icon={<IconWarn />}
              label="Alerts"
              active={tab === 'dashboard' && dashFocus === 'alerts'}
              onClick={() => { setTab('dashboard'); setDashFocus('alerts'); setSidebarOpen(false); }}
            />
          </div>

          <div className="ss7-nav__section">
            <p className="ss7-nav__section-title">Operations</p>
            <NavItem
              icon={<IconAllow />}
              label="Partners"
              active={tab === 'dashboard' && dashFocus === 'partners'}
              onClick={() => { setTab('dashboard'); setDashFocus('partners'); setSidebarOpen(false); }}
            />
            <NavItem
              icon={<IconLibrary />}
              label="Reports"
              active={tab === 'index'}
              onClick={() => { setTab('index'); setSidebarOpen(false); }}
            />
            <NavItem
              icon={<IconSearch />}
              label="Explorer"
              active={tab === 'structure'}
              onClick={() => { setTab('structure'); setSidebarOpen(false); }}
            />
          </div>
        </nav>

        <div className="ss7-sidebar__footer ss7-rail__footer">
          <NavItem
            icon={<IconLogout />}
            label="Logout"
            active={false}
            title={`Sign out ${session.name}`}
            onClick={onLogout}
          />
          {apiError && <p className="ss7-error">{apiError}</p>}
        </div>
      </aside>

      {sidebarOpen && (
        <button
          type="button"
          className="ss7-sidebar-scrim"
          aria-label="Close menu"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Main Content */}
      <main className="ss7-main">
        <header className="ss7-header ss7-topbar">
          <div className="ss7-header__left">
            <button
              type="button"
              className="ss7-header__menu"
              aria-label="Open menu"
              onClick={() => setSidebarOpen((v) => !v)}
            >
              <IconMenu />
            </button>
            <div className="ss7-topbar__brand-mobile">
              <Logo />
            </div>
            <nav className="ss7-crumbs" aria-label="Breadcrumb">
              <span>Telecom Cybersecurity</span>
              <em>/</em>
              <span>SOC</span>
              <em>/</em>
              <strong>{tab === 'chat' ? 'Research' : getPageTitle()}</strong>
            </nav>
            <label className="ss7-header__search ss7-topbar__search">
              <IconSearch />
              <input
                value={headerSearch}
                onChange={(e) => setHeaderSearch(e.target.value)}
                placeholder="Search IMSI, MSISDN, APN, IP, operator, rule..."
                aria-label="Global search"
              />
              <kbd>Ctrl + K</kbd>
            </label>
          </div>
          <div className="ss7-header__actions ss7-topbar__actions">
            <span className={`ss7-live${status ? ' ss7-live--on' : ''}`}>
              <span className="ss7-live__dot" />
              {status ? 'Connected · Live Network' : 'OFFLINE'}
            </span>
            <button type="button" className="ss7-topbar__iconbtn" aria-label="Notifications">
              <IconBell />
            </button>
            <div className="ss7-header__clock" title={clock.tz}>
              <span>{clock.date}</span>
              <strong>{clock.time}</strong>
            </div>
            <div className="ss7-userchip ss7-userchip--top" title={session?.name}>
              <div className="ss7-userchip__avatar">{(session?.user || 'sg').slice(0, 2).toUpperCase()}</div>
            </div>
            <button
              type="button"
              className="ss7-topbar__iconbtn"
              aria-label="Logout"
              title="Logout"
              onClick={onLogout}
            >
              <IconLogout />
            </button>
          </div>
        </header>

        <div className="ss7-content ss7-content--stage">
          {tab === 'dashboard' && <IDSDashboard initialTab={dashFocus} />}

          {tab === 'chat' && (
            <div className="ss7-chat ss7-chat--analyst">
              <aside className="ss7-chat__history ss7-chat__history--methods" aria-label="Methodology and chat history">
                <div className="ss7-chat__history-head">
                  <div>
                    <p className="ss7-chat__history-kicker">CORTES Playbook</p>
                    <h3>Methodology</h3>
                  </div>
                  <button
                    type="button"
                    className="ss7-chat__history-new"
                    onClick={() => startNewChat()}
                    title="New chat"
                  >
                    <IconPlus />
                    <span>New</span>
                  </button>
                </div>

                <div className="ss7-method-list" role="list">
                  {METHODOLOGY.map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      role="listitem"
                      className={`ss7-method${activeMethod === m.id ? ' is-active' : ''}`}
                      onClick={() => applyMethodology(m)}
                      title={m.blurb}
                    >
                      <span className="ss7-method__icon" aria-hidden>
                        {m.icon}
                      </span>
                      <span className="ss7-method__copy">
                        <strong>{m.label}</strong>
                        <em>{m.blurb}</em>
                      </span>
                    </button>
                  ))}
                </div>

                <div className="ss7-chat__history-divider">
                  <span>Sessions</span>
                </div>

                <label className="ss7-chat__history-search">
                  <IconSearch />
                  <input
                    value={chatHistoryQuery}
                    onChange={(e) => setChatHistoryQuery(e.target.value)}
                    placeholder="Search chats…"
                    aria-label="Search chat history"
                  />
                </label>

                <div className="ss7-chat__history-list">
                  {filteredConversations.length === 0 ? (
                    <div className="ss7-chat__history-empty">
                      <IconChat />
                      <p>{chatHistoryQuery.trim() ? 'No matching chats' : 'No conversations yet'}</p>
                      <span>{chatHistoryQuery.trim() ? 'Try another search' : 'Pick a methodology or start below'}</span>
                    </div>
                  ) : (
                    historyGroups.map((group) => (
                      <div className="ss7-chat__history-group" key={group.label}>
                        <div className="ss7-chat__history-label">{group.label}</div>
                        {group.items.map((c) => {
                          const title = c.title || c.first_message || 'Untitled chat'
                          const active = conversationId === c.id
                          return (
                            <div
                              key={c.id}
                              className={`ss7-chat__history-item${active ? ' is-active' : ''}`}
                              role="button"
                              tabIndex={0}
                              onClick={() => {
                                setActiveMethod(null)
                                loadConversation(c.id).catch((err) => setApiError(String(err)))
                              }}
                              onKeyDown={(ev) => {
                                if (ev.key === 'Enter' || ev.key === ' ') {
                                  ev.preventDefault()
                                  setActiveMethod(null)
                                  loadConversation(c.id).catch((err) => setApiError(String(err)))
                                }
                              }}
                            >
                              <div className="ss7-chat__history-item-main">
                                <strong title={title}>{title}</strong>
                                <em>{c.updated_at ? formatRelative(c.updated_at) : ''}</em>
                              </div>
                              <button
                                type="button"
                                className="ss7-chat__history-delete"
                                title="Delete chat"
                                aria-label="Delete chat"
                                onClick={(e) => onDeleteChat(c.id, e)}
                              >
                                ×
                              </button>
                            </div>
                          )
                        })}
                      </div>
                    ))
                  )}
                </div>
              </aside>

              <div className="ss7-chat__workspace">
                <div className="ss7-chat__toolbar">
                  <div className="ss7-chat__toolbar-title">
                    <span className="ss7-chat__toolbar-kicker">
                      {messages.length ? 'Active session' : 'Research console'}
                    </span>
                    <strong>{activeTitle}</strong>
                  </div>
                  <div className="ss7-chat__toolbar-actions">
                    <div className="ss7-chat__case-pills ss7-chat__case-pills--toolbar" role="tablist" aria-label="Case mode">
                      <button
                        type="button"
                        className={chatCase === 'case1' ? 'is-active' : ''}
                        onClick={() => setChatCase('case1')}
                      >
                        Live IDS
                      </button>
                      <button
                        type="button"
                        className={chatCase === 'case2' ? 'is-active' : ''}
                        onClick={() => setChatCase('case2')}
                      >
                        Standards
                      </button>
                      <button
                        type="button"
                        className={chatCase === 'case3' ? 'is-active' : ''}
                        onClick={() => setChatCase('case3')}
                      >
                        Rules
                      </button>
                    </div>
                    <button
                      type="button"
                      className="ss7-chat__toolbar-new"
                      onClick={() => startNewChat()}
                    >
                      <IconPlus /> New chat
                    </button>
                  </div>
                </div>

                <div className={`ss7-chat__messages${messages.length ? ' has-thread' : ''}`} ref={scrollRef}>
                  {messages.length === 0 && (
                    <div className="ss7-chat__empty">
                      <div className="ss7-empty-hero ss7-empty-hero--tower" aria-hidden>
                        <div className="ss7-empty-hero__rings" />
                        <div className="ss7-empty-hero__glyph">
                          <svg viewBox="0 0 48 48" width="34" height="34" fill="none">
                            <path d="M24 6 10 12v10c0 9 6 16.5 14 19 8-2.5 14-10 14-19V12L24 6Z" stroke="currentColor" strokeWidth="2" />
                            <path d="M24 16v14M18 22h12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                            <path d="M20 30h8M22 34h4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                            <circle cx="24" cy="18" r="1.8" fill="currentColor" />
                          </svg>
                        </div>
                      </div>
                      <p className="ss7-chat__kicker">CORTES ANALYST</p>
                      <h2>
                        Command the <span className="ss7-accent">interconnect edge</span>
                      </h2>
                      <p className="ss7-chat__lead">
                        Ask standards questions, draft CAT rules, or attach live IDS observations for Case 1 decisions.
                      </p>
                      <div className="ss7-chat__starters">
                        {(
                          status?.sample_questions?.length
                            ? status.sample_questions
                            : [
                                'What is a Category-1 signaling message?',
                                'Which SS7 messages are prohibited on an international roaming interface?',
                                'What is the difference between Category-2 and Category-3 signaling?',
                                'Draft a CAT2 Diameter realm validation rule',
                                'Explain FS.11 filtering requirements for MAP',
                                'Why would an Update-Location-Request escalate?',
                              ]
                        )
                          .slice(0, 6)
                          .map((q, i) => (
                            <button
                              key={q}
                              type="button"
                              className={`ss7-chat__starter ss7-chat__starter--tone${(i % 6) + 1}`}
                              onClick={() => onSend(undefined, q)}
                            >
                              <span className="ss7-chat__starter-icon">
                                {i % 6 === 0 ? <IconInspect /> : null}
                                {i % 6 === 1 ? <IconLibrary /> : null}
                                {i % 6 === 2 ? <IconShield /> : null}
                                {i % 6 === 3 ? <IconPulse /> : null}
                                {i % 6 === 4 ? <IconWarn /> : null}
                                {i % 6 === 5 ? <IconSpark /> : null}
                              </span>
                              <span className="ss7-chat__starter-text">{q}</span>
                              <span className="ss7-chat__starter-go" aria-hidden>
                                →
                              </span>
                            </button>
                          ))}
                      </div>
                    </div>
                  )}

                  {messages.map((msg) =>
                    msg.role === 'user' ? (
                      <div className="ss7-msg ss7-msg--user" key={msg.id}>
                        <div className="ss7-msg__bubble ss7-msg__bubble--user">{msg.content}</div>
                      </div>
                    ) : (
                      <div className="ss7-msg ss7-msg--assistant" key={msg.id}>
                        <div className="ss7-msg__avatar" aria-hidden>CR</div>
                        <div className="ss7-msg__body">
                          {msg.content ? (
                            <div className="ss7-msg__md md answer-md">
                              <Markdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
                                {msg.content}
                              </Markdown>
                            </div>
                          ) : null}
                          {!msg.content && msg.mode === 'agentic' ? (
                            <PipelineCard
                              kind="agentic"
                              data={msg.agent}
                              pending={
                                msg.streaming
                                  ? 'streaming…'
                                  : msg.agent
                                    ? undefined
                                    : msg.status || 'Working…'
                              }
                            />
                          ) : !msg.content ? (
                            <div className="compare">
                              <PipelineCard
                                kind="original"
                                data={msg.original}
                                pending={msg.original ? undefined : msg.status || 'Working…'}
                              />
                              <PipelineCard
                                kind="docling"
                                data={msg.docling}
                                pending={
                                  msg.docling
                                    ? undefined
                                    : msg.original
                                      ? 'Generating DOCLING (hybrid)…'
                                      : msg.status || 'Waiting for retrieval…'
                                }
                              />
                            </div>
                          ) : null}
                        </div>
                      </div>
                    ),
                  )}
                </div>

                <div className="ss7-chat__composer">
                  <form className="ss7-composer ss7-composer--pill" onSubmit={onSend}>
                    <button type="button" className="ss7-composer__tool" aria-label="Attach" title="Attach">
                      <IconPlus />
                    </button>
                    <textarea
                      ref={inputRef}
                      rows={1}
                      placeholder="Message CORTES"
                      value={input}
                      onChange={(e) => {
                        setInput(e.target.value)
                        resizeComposer(e.target)
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault()
                          onSend()
                        }
                      }}
                    />
                    <button type="button" className="ss7-composer__tool" aria-label="Voice" title="Voice">
                      <IconPulse />
                    </button>
                    {busy ? (
                      <button className="ss7-composer__send ss7-composer__send--stop" type="button" onClick={onStop} aria-label="Stop">
                        <IconStop />
                      </button>
                    ) : (
                      <button className="ss7-composer__send" type="submit" disabled={!input.trim()} aria-label="Send">
                        <IconSend />
                      </button>
                    )}
                  </form>
                  <div className="ss7-composer__context" aria-hidden>
                    <strong>
                      {chatCase === 'case1' ? 'Live IDS' : chatCase === 'case2' ? 'Standards RAG' : 'Rule Design'}
                    </strong>
                    <em>|</em>
                    <span>Network + Standards + Rules</span>
                  </div>
                </div>
              </div>

              <aside className="ss7-intel-pane">
                <div className="ss7-intel-pane__block">
                  <h3>Network Intelligence</h3>
                  <button type="button" className="ss7-intel-link" onClick={() => { setTab('dashboard'); setDashFocus('traffic') }}>
                    <IconPulse /> Live Network View <span>›</span>
                  </button>
                  <button type="button" className="ss7-intel-link" onClick={() => setChatCase('case2')}>
                    <IconLibrary /> Standards & RAG <span>›</span>
                  </button>
                  <button type="button" className="ss7-intel-link" onClick={() => { setTab('dashboard'); setDashFocus('rules') }}>
                    <IconInspect /> Rule Analysis <span>›</span>
                  </button>
                </div>
                <div className="ss7-intel-pane__block">
                  <h3>Quick Context</h3>
                  <ul className="ss7-context-list">
                    <li><span>✓</span> 3GPP TS 29.002</li>
                    <li><span>✓</span> GSMA FS.11</li>
                    <li><span>✓</span> GSMA FS.19</li>
                    <li><span>✓</span> IR.21 Partner DB</li>
                    <li><span>✓</span> CAT1–CAT3 Rules</li>
                  </ul>
                </div>
                <div className="ss7-intel-pane__wave" aria-hidden>
                  <div className="ss7-intel-pane__tower" />
                </div>
              </aside>
            </div>
          )}

          {tab === 'index' && (
            <div className="ss7-panel ss7-panel--soc">
              <div className="ss7-pagehead">
                <div>
                  <p className="ss7-pagehead__kicker">Knowledge Plane</p>
                  <h2>Knowledge Base</h2>
                  <p>Enroll IR.21 partners, GSMA FS specs, and operator policy into structured + vector stores for Case 2/3 RAG.</p>
                </div>
                <span className={`ss7-live${status ? ' ss7-live--on' : ''}`}>
                  <span className="ss7-live__dot" />
                  {status ? 'INDEX READY' : 'OFFLINE'}
                </span>
              </div>

              <div className="ss7-kb-grid">
                <div className="ss7-upload-card">
                  <div className="ss7-upload__toggle" role="group" aria-label="Enrollment mode">
                    <button
                      type="button"
                      className={enrollmentMode === 'structured' ? 'active' : ''}
                      disabled={indexBusy}
                      onClick={() => setEnrollmentMode('structured')}
                    >
                      Structured
                    </button>
                    <button
                      type="button"
                      className={enrollmentMode === 'vector' ? 'active' : ''}
                      disabled={indexBusy}
                      onClick={() => setEnrollmentMode('vector')}
                    >
                      Vector Only
                    </button>
                  </div>

                  <p className="ss7-upload__desc">
                    {enrollmentMode === 'structured'
                      ? 'Full extraction: Facts, tables, entity graph, and vector embeddings'
                      : 'Vector embeddings only (faster, no structured data)'}
                  </p>

                  <label className={`ss7-upload__zone ${indexBusy ? 'disabled' : ''}`}>
                    <input
                      type="file"
                      accept={enrollmentMode === 'structured' ? '.pdf,.txt,.md' : '.pdf'}
                      multiple
                      hidden
                      disabled={indexBusy}
                      onChange={(e) => {
                        const pipelines = enrollmentMode === 'structured' ? ['docling'] : ['original']
                        const label = enrollmentMode === 'structured' ? 'structured' : 'vector only'
                        onIndex(e.target.files, pipelines, label)
                        e.target.value = ''
                      }}
                    />
                    {indexBusy ? (
                      'Indexing…'
                    ) : (
                      <>
                        <IconUpload />
                        <span>Drop files or click to enroll</span>
                      </>
                    )}
                  </label>

                  <button
                    type="button"
                    className="ss7-btn"
                    disabled={indexBusy}
                    onClick={() => {
                      const pipelines = enrollmentMode === 'structured' ? ['docling'] : ['original']
                      const label = enrollmentMode === 'structured' ? 'structured sample' : 'vector sample'
                      onSample(pipelines, label)
                    }}
                  >
                    Index Sample Document
                  </button>
                </div>

                <div className="ss7-kb-side">
                  <div className="ss7-stat-tile">
                    <span>Documents</span>
                    <strong>{(status?.documents || []).length}</strong>
                  </div>
                  <div className="ss7-stat-tile">
                    <span>LLM</span>
                    <strong style={{ fontSize: '0.95rem' }}>{status?.gemma || '—'}</strong>
                  </div>
                  <div className="ss7-section" style={{ marginTop: 0 }}>
                    <h3>Maintenance</h3>
                    <div className="ss7-actions">
                      <button type="button" className="ss7-btn ss7-btn--danger" disabled={indexBusy} onClick={onClearEnrollment}>
                        Clear All
                      </button>
                      <button type="button" className="ss7-btn" disabled={indexBusy} onClick={onRefreshStructured}>
                        Refresh DB
                      </button>
                      <button type="button" className="ss7-btn" disabled={indexBusy} onClick={onRefreshEmbeddings}>
                        Sync Vectors
                      </button>
                      <button type="button" className="ss7-btn ss7-btn--primary" disabled={indexBusy} onClick={onRefreshAll}>
                        Refresh All
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {indexLog && <pre className="ss7-log">{indexLog}</pre>}
            </div>
          )}

          {tab === 'structure' && (
            <div className="ss7-panel ss7-panel--soc">
              <div className="ss7-pagehead">
                <div>
                  <p className="ss7-pagehead__kicker">Corpus Inspector</p>
                  <h2>Document Explorer</h2>
                  <p>Walk the table of contents, sections, and chunk types for every enrolled document.</p>
                </div>
              </div>
              <div className="ss7-explorer-bar">
                <div className="ss7-field" style={{ flex: 1, maxWidth: 480, marginBottom: 0 }}>
                  <label>Select Document</label>
                  <select
                    value={structureSelected}
                    onChange={(e) => {
                      const v = e.target.value
                      setStructureSelected(v)
                      loadStructure(v).catch((err) => setStructureReport(String(err)))
                    }}
                  >
                    {structureDocs.length === 0 && <option value="">No documents</option>}
                    {structureDocs.map((d) => (
                      <option key={d} value={d}>{d}</option>
                    ))}
                  </select>
                </div>
                <button type="button" className="ss7-btn" onClick={() => loadStructure(structureSelected)}>
                  <IconRefresh /> Refresh
                </button>
              </div>
              <div className="ss7-structure-md" style={{ marginTop: '1rem' }}>
                {structureReport ? (
                  <Markdown remarkPlugins={[remarkGfm]}>{structureReport}</Markdown>
                ) : (
                  <div className="ss7-empty-state">Select a document to inspect its structure.</div>
                )}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
