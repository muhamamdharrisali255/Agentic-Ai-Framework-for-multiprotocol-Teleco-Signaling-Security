export interface IDSMetrics {
  packets_inspected: number
  packets_allowed: number
  packets_blocked: number
  packets_escalated: number
  cat1_matches: number
  cat2_blocks: number
  cat3_escalations: number
  avg_latency_ms: number
  active_threats: number
  running: boolean
  enforcement_mode: string
  dry_run: boolean
  uptime_seconds: number
}

export interface TrafficEvent {
  event_id: string
  timestamp: string
  protocol: string
  source: string
  destination: string
  global_title?: string
  origin_realm?: string
  procedure: string
  subscriber_id_masked?: string
  category: string
  decision: string
  rule_id?: string
  confidence: number
  processing_latency_ms: number
}

export interface Alert {
  alert_id: string
  timestamp: string
  category: string
  severity: string
  title: string
  description: string
  decision: string
  attack_pattern?: string
  detection_rule?: string
  packet_event_id?: string
  subscriber_id_masked?: string
  evidence?: Record<string, unknown>
  acknowledged: boolean
  analyst_note?: string
}

export interface InspectionResult {
  event_id: string
  decision: string
  category: string
  confidence: number
  enforcement: string
  dry_run: boolean
  reason: string
  processing_latency_ms: number
  cat1_result?: Record<string, unknown>
  cat2_result?: Record<string, unknown>
  cat3_result?: Record<string, unknown>
}

export interface InvestigationBrief {
  event_id: string
  decision: string
  category: string
  reason: string
  explanation: string
  confidence?: number
  enforcement?: string
  dry_run?: boolean
  attack_pattern?: string
  detection_rule?: string
  rule?: Partial<Rule> & {
    validation_logic?: string
    ir21_checks?: string[]
    reference?: string
  } | null
  rule_match?: Record<string, unknown> | null
  validation?: Record<string, unknown> | null
  ir_evidence?: {
    document?: string
    section?: string
    partner_id?: string
    matched_fields?: string[]
    expected_values?: Record<string, unknown>
    observed_values?: Record<string, unknown>
    mismatches?: string[]
  } | null
  subscriber_analysis?: {
    subscriber_id_masked?: string
    distance_km?: number
    delta_seconds?: number
    required_velocity_kmh?: number
    max_plausible_velocity_kmh?: number
    sequence_valid?: boolean
    flags?: string[]
    previous_location?: Record<string, unknown>
    current_location?: Record<string, unknown>
  } | null
  stages?: Array<Record<string, unknown>>
  alert?: Alert | null
}

export interface DumpReplayEventResult {
  id?: string
  kind?: string
  decision?: string
  category?: string
  reason?: string
  rule?: string
  sid?: number | string
  ok?: boolean
  detail?: string
  blocked?: boolean
  ips?: {
    blocked?: boolean
    action?: string
    category?: string
    protocol?: string
    rules?: number
  }
}

export interface DumpReplayResult {
  dump: string
  rules: number
  traffic: number
  passed: number
  failed: number
  published: number
  ok: boolean
  results: DumpReplayEventResult[]
}

export interface Rule {
  rule_id: string
  sid?: number
  name: string
  description?: string
  category: string
  protocol: string
  generation?: string
  attack_pattern?: string
  action?: string
  enabled: boolean
  severity: string
  opcode?: number
  procedure?: string
  direction?: string
  ir21_checks?: string[]
  analysis_type?: string
  ai_model?: string
  parameters?: Record<string, unknown>
  rule_text?: string
  reference?: string
  summary?: string
  validation_logic?: string
}

export interface Partner {
  partner_id: string
  operator_name: string
  country: string
  mcc: string
  mnc: string
  tadig_code: string
  document_id?: string
  agreement_status: string
  ss7: {
    gt_prefixes: string[]
    smsc_gts: string[]
    map_versions: string[]
    cap_versions: string[]
  }
  diameter: {
    origin_realm: string
    origin_hosts: string[]
    diameter_applications: string[]
    lte_roaming: boolean
  }
  gtp: {
    allowed_apns: string[]
    gtp_version: string
    ip_ranges: string[]
    data_roaming: boolean
  }
}

export type DashboardTab =
  | 'overview'
  | 'traffic'
  | 'alerts'
  | 'partners'
  | 'rules'
  | 'threats'
  | 'analytics'
  | 'summary'

export type TimeRange = '1H' | '24H' | '7D' | '30D'
