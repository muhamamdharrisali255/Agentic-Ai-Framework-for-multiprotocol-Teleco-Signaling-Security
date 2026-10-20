export type KSuiteCase = {
  id: string
  q: string
  expect?: string
}

export type StatusResponse = {
  pipelines: { name: string; chunks: number; documents: string[] }[]
  hybrid: {
    enabled: boolean
    sql_backend?: string
    graph_backend?: string
    structured_docs?: string[]
    error?: string
  }
  embedding_model: string
  embedding_device: string
  gemma: string
  gemma_model: string
  top_k_default: number
  sample_questions: string[]
  k_suite?: KSuiteCase[]
  documents: string[]
  agentic_rag?: boolean
}

export type ChunkHit = {
  rank: number
  score: number
  chunk_id: string
  content_type: string
  page?: number | null
  section?: string
  toc_path?: string
  file_name?: string
  table_id?: string
  preview: string
  fs_doc?: string | null
}

export type PipelineResult = {
  pipeline: string
  answer: string
  ms: number
  hits: number
  sources: string[]
  chunks: ChunkHit[]
  hybrid?: string
  pending_other?: boolean
  query_type?: string
  confidence?: string
  tools_used?: string[]
  stages?: string[]
  finding?: {
    finding?: string
    confidence?: string
    confidence_score?: number
    severity?: string
    recommendation?: string
  }
  agent_context?: Record<string, unknown>
  round1_documents?: { file_name: string; score: number; source?: string }[]
  specialists?: string[]
  knowledge_kinds?: string[]
  knowledge_domain?: string
  domain_meta?: Record<string, unknown>
  detection_rules?: { rule?: string; sid?: string; source?: string; grounded?: boolean; note?: string }[]
  reports?: { agent: string; store: string; hits: number; ok?: boolean; latency_ms?: number }[]
}

async function readError(res: Response): Promise<string> {
  const url = res.url || '(unknown url)'
  try {
    const j = await res.json()
    const detail = j.detail || j.error || res.statusText
    return `HTTP ${res.status} on ${url}: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`
  } catch {
    return `HTTP ${res.status} on ${url}: ${res.statusText || 'request failed'}`
  }
}

export async function fetchStatus(): Promise<StatusResponse> {
  const res = await fetch('/api/status')
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export async function fetchStructure(document?: string) {
  const q = document ? `?document=${encodeURIComponent(document)}` : ''
  const res = await fetch(`/api/structure${q}`)
  if (!res.ok) throw new Error(await readError(res))
  return res.json() as Promise<{
    documents: string[]
    selected: string | null
    report: string | null
    error?: string
  }>
}

export async function indexFiles(files: FileList | File[], pipelines: string[]) {
  const fd = new FormData()
  Array.from(files).forEach((f) => fd.append('files', f))
  fd.append('pipelines', pipelines.join(','))
  const res = await fetch('/api/index', { method: 'POST', body: fd })
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export async function indexSample(pipelines: string[]) {
  const res = await fetch(`/api/index/sample?pipelines=${encodeURIComponent(pipelines.join(','))}`, {
    method: 'POST',
  })
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export async function refreshStructured() {
  const res = await fetch('/api/admin/refresh-structured', { method: 'POST' })
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export async function refreshEmbeddings(pipeline: 'both' | 'docling' | 'original' = 'both') {
  const res = await fetch('/api/admin/refresh-embeddings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pipeline }),
  })
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export async function refreshAllData() {
  const res = await fetch('/api/admin/refresh-all', { method: 'POST' })
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export async function clearEnrollment() {
  const res = await fetch('/api/admin/clear-enrollment', { method: 'POST' })
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export type ConversationSummary = {
  id: string
  title: string
  document_filter?: string | null
  top_k?: number
  created_at?: string
  updated_at?: string
  first_message?: string | null
}

export type StoredMessage = {
  id: string
  conversation_id: string
  role: 'user' | 'assistant'
  content?: string | null
  metadata?: {
    agent?: PipelineResult
    mode?: string
    original?: PipelineResult
    docling?: PipelineResult
  }
  created_at?: string
}

export async function fetchConversations(): Promise<ConversationSummary[]> {
  const res = await fetch('/api/conversations')
  if (!res.ok) throw new Error(await readError(res))
  const data = await res.json()
  return data.conversations || []
}

export async function createConversation(title = 'New chat'): Promise<ConversationSummary> {
  const res = await fetch('/api/conversations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title }),
  })
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export async function fetchConversation(id: string): Promise<{
  conversation: ConversationSummary
  messages: StoredMessage[]
}> {
  const res = await fetch(`/api/conversations/${encodeURIComponent(id)}`)
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export async function deleteConversation(id: string): Promise<void> {
  const res = await fetch(`/api/conversations/${encodeURIComponent(id)}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await readError(res))
}

export type ChatHandlers = {
  onStatus: (text: string, stage: string) => void
  onOriginal: (data: PipelineResult) => void
  onDocling: (data: PipelineResult) => void
  onAgent: (data: PipelineResult) => void
  onToken?: (text: string) => void
  onTokenReset?: () => void
  onConversationId: (id: string) => void
  onDone: () => void
  onError: (err: string) => void
}

type AskPayload = {
  error?: string
  mode?: string
  agent?: PipelineResult
  original?: PipelineResult
  docling?: PipelineResult
  answer?: string
  chunks?: ChunkHit[]
  hits?: number
  ms?: number
  latency_ms?: number
  sources?: string[]
  candidate_sources?: string[]
  hybrid?: string
  query_type?: string
  confidence?: string
  tools_used?: string[]
  pipeline?: string
  conversation_id?: string
  stages?: string[]
  finding?: PipelineResult['finding']
  agent_context?: Record<string, unknown>
  round1_documents?: PipelineResult['round1_documents']
  specialists?: string[]
  knowledge_kinds?: string[]
  knowledge_domain?: string
  domain_meta?: Record<string, unknown>
  detection_rules?: PipelineResult['detection_rules']
  reports?: PipelineResult['reports']
}

function normalizeAgentPayload(raw: AskPayload | PipelineResult): PipelineResult | null {
  if (!raw || typeof raw !== 'object') return null
  const answer = raw.answer
  if (typeof answer !== 'string' || !answer.trim()) return null

  const chunks = raw.chunks ?? []
  const tools = raw.tools_used ?? []
  const latencyMs = 'latency_ms' in raw ? raw.latency_ms : undefined
  const candidateSources = 'candidate_sources' in raw ? raw.candidate_sources : undefined
  return {
    pipeline: 'agentic',
    answer,
    ms: Number(raw.ms ?? latencyMs ?? 0),
    hits: Number(raw.hits ?? chunks.length ?? 0),
    sources: raw.sources ?? candidateSources ?? [],
    chunks,
    hybrid: raw.hybrid ?? (tools.length ? tools.join(',') : undefined),
    query_type: raw.query_type,
    confidence: raw.confidence,
    tools_used: tools,
    stages: 'stages' in raw ? raw.stages : undefined,
    finding: 'finding' in raw ? raw.finding : undefined,
    agent_context: 'agent_context' in raw ? raw.agent_context : undefined,
    round1_documents: 'round1_documents' in raw ? raw.round1_documents : undefined,
    specialists: 'specialists' in raw ? raw.specialists : undefined,
    knowledge_kinds: 'knowledge_kinds' in raw ? raw.knowledge_kinds : undefined,
    knowledge_domain: 'knowledge_domain' in raw ? raw.knowledge_domain : undefined,
    domain_meta: 'domain_meta' in raw ? raw.domain_meta : undefined,
    detection_rules: 'detection_rules' in raw ? raw.detection_rules : undefined,
    reports: 'reports' in raw ? raw.reports : undefined,
  }
}

function parseAskPayload(payload: AskPayload):
  | { kind: 'agentic'; agent: PipelineResult }
  | { kind: 'dual'; original: PipelineResult; docling: PipelineResult }
  | { kind: 'error'; message: string } {
  if (payload.error) {
    return { kind: 'error', message: payload.error }
  }

  const nested = payload.agent ? normalizeAgentPayload(payload.agent) : null
  if (nested) {
    return { kind: 'agentic', agent: nested }
  }

  if (payload.mode === 'agentic' || payload.pipeline === 'agentic') {
    const flat = normalizeAgentPayload(payload)
    if (flat) {
      return { kind: 'agentic', agent: flat }
    }
  }

  if (!payload.original && !payload.docling && payload.answer) {
    const flat = normalizeAgentPayload(payload)
    if (flat) {
      return { kind: 'agentic', agent: flat }
    }
  }

  if (payload.original && payload.docling) {
    return { kind: 'dual', original: payload.original, docling: payload.docling }
  }

  return {
    kind: 'error',
    message: 'Incomplete response from /api/ask (expected agentic or dual pipeline data)',
  }
}

/** Prefer SSE token stream so the UI paints as the model generates. */
export async function streamChat(
  message: string,
  topK: number,
  document: string | null,
  handlers: ChatHandlers,
  signal?: AbortSignal,
  conversationId?: string | null,
) {
  handlers.onStatus('Retrieving ranked evidence…', 'retrieve')

  try {
    await streamChatSse(message, topK, document, handlers, signal, conversationId)
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      handlers.onError('Request aborted.')
      handlers.onDone()
      return
    }
    handlers.onStatus('SSE unavailable — using JSON fallback…', 'retrieve')
    await streamChatJson(message, topK, document, handlers, signal, conversationId)
  }
}

async function streamChatJson(
  message: string,
  topK: number,
  document: string | null,
  handlers: ChatHandlers,
  signal?: AbortSignal,
  conversationId?: string | null,
) {
  const body = JSON.stringify({
    message,
    top_k: topK,
    document: document && document !== 'All documents' ? document : null,
    conversation_id: conversationId || null,
  })

  const ac = new AbortController()
  const onAbort = () => ac.abort()
  signal?.addEventListener('abort', onAbort)
  const timer = window.setTimeout(() => ac.abort(), 240_000)

  let finished = false
  const finish = () => {
    if (finished) return
    finished = true
    handlers.onDone()
  }

  let res: Response
  try {
    res = await fetch('/api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body,
      signal: ac.signal,
    })
  } catch (err) {
    window.clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
    if ((err as Error).name === 'AbortError') {
      handlers.onError(
        'Request timed out after 240s (GPU/LLM may be busy). Retry once the model is loaded.',
      )
    } else {
      handlers.onError(`Network error calling /api/ask: ${String(err)}`)
    }
    finish()
    return
  }
  window.clearTimeout(timer)
  signal?.removeEventListener('abort', onAbort)

  if (!res.ok) {
    handlers.onError(await readError(res))
    finish()
    return
  }

  let payload: AskPayload
  try {
    payload = await res.json()
  } catch (err) {
    handlers.onError(`Invalid JSON from /api/ask: ${String(err)}`)
    finish()
    return
  }

  if (payload.conversation_id) {
    handlers.onConversationId(payload.conversation_id)
  }

  const parsed = parseAskPayload(payload)
  if (parsed.kind === 'error') {
    handlers.onError(parsed.message)
    finish()
    return
  }
  if (parsed.kind === 'agentic') {
    handlers.onAgent(parsed.agent)
    finish()
    return
  }

  handlers.onOriginal(parsed.original)
  handlers.onDocling(parsed.docling)
  finish()
}

async function streamChatSse(
  message: string,
  topK: number,
  document: string | null,
  handlers: ChatHandlers,
  signal?: AbortSignal,
  conversationId?: string | null,
) {
  const res = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
    body: JSON.stringify({
      message,
      top_k: topK,
      document: document && document !== 'All documents' ? document : null,
      conversation_id: conversationId || null,
    }),
    signal,
  })
  if (!res.ok || !res.body) {
    throw new Error(await readError(res))
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let sawDone = false

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const parts = buffer.split('\n\n')
    buffer = parts.pop() || ''
    for (const part of parts) {
      const lines = part.split('\n')
      let event = 'message'
      let data = ''
      for (const line of lines) {
        if (line.startsWith('event:')) event = line.slice(6).trim()
        if (line.startsWith('data:')) data += line.slice(5).trim()
      }
      if (!data) continue
      try {
        const payload = JSON.parse(data)
        if (event === 'status') handlers.onStatus(payload.text || '', payload.stage || '')
        else if (event === 'token_reset') handlers.onTokenReset?.()
        else if (event === 'token') handlers.onToken?.(payload.text || '')
        else if (event === 'conversation' && payload.conversation_id) {
          handlers.onConversationId(payload.conversation_id)
        }
        else if (event === 'agent') handlers.onAgent(payload)
        else if (event === 'original') handlers.onOriginal(payload)
        else if (event === 'docling') handlers.onDocling(payload)
        else if (event === 'error') handlers.onError(payload.detail || 'chat failed')
        else if (event === 'done') {
          if (payload.conversation_id) handlers.onConversationId(payload.conversation_id)
          sawDone = true
          handlers.onDone()
        }
      } catch {
        /* ignore partial json */
      }
    }
  }
  if (!sawDone) {
    handlers.onError(
      'Connection closed before the answer finished (server may have restarted or run out of GPU memory). Retry once the local model is loaded.',
    )
  }
}
