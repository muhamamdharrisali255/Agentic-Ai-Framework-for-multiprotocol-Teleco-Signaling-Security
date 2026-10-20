import type {
  Alert,
  DumpReplayResult,
  IDSMetrics,
  InspectionResult,
  InvestigationBrief,
  Partner,
  Rule,
  TrafficEvent,
} from '../types/ids'

const API_BASE = '/api'

interface RawEvent {
  event_id?: string
  timestamp?: string
  category?: string
  data?: Partial<TrafficEvent> & { event_id?: string; timestamp?: string }
}

export async function fetchIDSStatus(): Promise<IDSMetrics> {
  const res = await fetch(`${API_BASE}/ids/status`)
  if (!res.ok) throw new Error(`Status fetch failed: ${res.status}`)
  const data = await res.json()
  return { ...data, ...data.metrics }
}

export async function startIDS(): Promise<void> {
  await fetch(`${API_BASE}/ids/start`, { method: 'POST' })
}

export async function stopIDS(): Promise<void> {
  await fetch(`${API_BASE}/ids/stop`, { method: 'POST' })
}

export async function setEnforcementMode(enforce: boolean): Promise<void> {
  await fetch(`${API_BASE}/ids/enforcement?enforce=${enforce}`, { method: 'POST' })
}

export async function fetchAlerts(limit = 50): Promise<Alert[]> {
  const res = await fetch(`${API_BASE}/ids/alerts?limit=${limit}`)
  if (!res.ok) return []
  const data = await res.json()
  return data.alerts || []
}

export async function fetchTraffic(limit = 50): Promise<TrafficEvent[]> {
  const res = await fetch(`${API_BASE}/ids/traffic?limit=${limit}`)
  if (!res.ok) return []
  const data = await res.json()
  return (data.events || []).map((e: RawEvent) => ({
    event_id: e.event_id || e.data?.event_id || '',
    timestamp: e.timestamp || e.data?.timestamp || '',
    protocol: e.data?.protocol || '',
    source: e.data?.source || '',
    destination: e.data?.destination || '',
    global_title: e.data?.global_title,
    origin_realm: e.data?.origin_realm,
    procedure: e.data?.procedure || '',
    subscriber_id_masked: e.data?.subscriber_id_masked,
    category: e.category || e.data?.category || '',
    decision: e.data?.decision || '',
    rule_id: e.data?.rule_id,
    confidence: e.data?.confidence || 1,
    processing_latency_ms: e.data?.processing_latency_ms || 0,
  }))
}

export async function fetchRules(): Promise<Rule[]> {
  const res = await fetch(`${API_BASE}/ids/rules`)
  if (!res.ok) return []
  const data = await res.json()
  return data.rules || []
}

export async function fetchPartners(): Promise<Partner[]> {
  const res = await fetch(`${API_BASE}/ids/partners`)
  if (!res.ok) return []
  const data = await res.json()
  return data.partners || []
}

export async function syncCdrNew(): Promise<{
  ok: boolean
  message: string
  partners: number
  stats?: Record<string, number>
}> {
  const res = await fetch(`${API_BASE}/ids/cdr/sync-new`, { method: 'POST' })
  if (!res.ok) {
    const detail = await res.text().catch(() => '')
    throw new Error(detail || `CDR Sync New failed: ${res.status}`)
  }
  return res.json()
}

export async function acknowledgeAlert(alertId: string, note = ''): Promise<void> {
  await fetch(`${API_BASE}/ids/alerts/${alertId}/acknowledge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note }),
  })
}

export async function investigateEvent(params: {
  eventId?: string
  alertId?: string
  ruleId?: string
}): Promise<InvestigationBrief> {
  const q = new URLSearchParams()
  if (params.eventId) q.set('event_id', params.eventId)
  if (params.alertId) q.set('alert_id', params.alertId)
  if (params.ruleId) q.set('rule_id', params.ruleId)
  const res = await fetch(`${API_BASE}/ids/investigate?${q.toString()}`)
  if (!res.ok) {
    const detail = await res.text().catch(() => '')
    throw new Error(detail || `Investigate failed: ${res.status}`)
  }
  return res.json()
}

export async function runDemo(type: 'cat1' | 'cat2' | 'cat3'): Promise<InspectionResult> {
  const res = await fetch(`${API_BASE}/ids/demo/${type}`, { method: 'POST' })
  if (!res.ok) throw new Error(`Demo failed: ${res.status}`)
  return res.json()
}

export async function replayDump(path = ''): Promise<DumpReplayResult> {
  const q = path ? `?path=${encodeURIComponent(path)}` : ''
  const res = await fetch(`${API_BASE}/ids/replay${q}`, { method: 'POST' })
  if (!res.ok) {
    const detail = await res.text().catch(() => '')
    throw new Error(detail || `Replay failed: ${res.status}`)
  }
  return res.json()
}

export function idsLiveWsUrl(): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}/api/ids/live`
}
