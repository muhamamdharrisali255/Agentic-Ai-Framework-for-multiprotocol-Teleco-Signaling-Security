/**
 * SignalGuard SOC Dashboard — premium command-center UI
 * Preserves live IDS REST + WebSocket data paths.
 */

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { FC, ReactNode } from 'react'
import {
  Bar,
  Cell,
  ComposedChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts'
import {
  acknowledgeAlert,
  fetchAlerts,
  fetchIDSStatus,
  fetchPartners,
  fetchRules,
  fetchTraffic,
  idsLiveWsUrl,
  investigateEvent,
  setEnforcementMode,
  startIDS,
  stopIDS,
} from './api/idsApi'
import {
  IconBell,
  IconBlock,
  IconClose,
  IconInspect,
  IconPulse,
  IconRefresh,
  IconShield,
  IconWarn,
} from './icons'
import { classNames, formatDuration, formatRelative, formatTime } from './lib/format'
import type {
  Alert,
  DashboardTab,
  IDSMetrics,
  InvestigationBrief,
  Partner,
  Rule,
  TrafficEvent,
} from './types/ids'

/* ---------- helpers ---------- */

const CHART_TOOLTIP = {
  background: 'rgba(10, 23, 48, 0.95)',
  border: '1px solid rgba(34, 211, 238, 0.22)',
  borderRadius: 10,
  fontSize: 12,
  color: '#F1F6FF',
  boxShadow: '0 12px 32px rgba(0,0,0,0.35)',
} as const

const CHART_TICK = { fill: '#5F7699', fontSize: 11, fontFamily: 'Outfit, system-ui, sans-serif' } as const
const CHART_GRID = 'rgba(95, 118, 153, 0.12)'

const CHART_COLORS = {
  cyan: '#22D3EE',
  green: '#10D9A0',
  red: '#F43F5E',
  amber: '#F5A524',
  purple: '#A855F7',
  blue: '#3B82F6',
} as const

function titleCaseKind(kind: string): string {
  if (!kind) return '—'
  return kind.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function formatUtcClock(iso: string): string {
  try {
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return iso
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
  } catch {
    return iso
  }
}

function badgeTone(status: string): string {
  const map: Record<string, string> = {
    ONLINE: 'ids-badge--cyan',
    OFFLINE: 'ids-badge--red',
    DRY_RUN: 'ids-badge--amber',
    ENFORCE: 'ids-badge--cyan',
    ACTIVE: 'ids-badge--cyan',
    BLOCKED: 'ids-badge--red',
    BLOCK: 'ids-badge--red',
    ESCALATE: 'ids-badge--amber',
    ALLOW: 'ids-badge--green',
    PASSED: 'ids-badge--green',
    CAT1: 'ids-badge--cyan',
    CAT2: 'ids-badge--purple',
    CAT3: 'ids-badge--amber',
    'CAT3.1': 'ids-badge--amber',
    'CAT3.2': 'ids-badge--amber',
    SYSTEM: 'ids-badge--cyan',
    CRITICAL: 'ids-badge--red',
    HIGH: 'ids-badge--red',
    MEDIUM: 'ids-badge--amber',
    LOW: 'ids-badge--blue',
    INFO: 'ids-badge--cyan',
  }
  return map[status] || map[status.toUpperCase()] || 'ids-badge--blue'
}

function StatusBadge({ status, pulse }: { status: string; pulse?: boolean }) {
  const label = (status || '—').toUpperCase()
  return (
    <span className={classNames('ids-badge', badgeTone(status), pulse && 'ids-badge--pulse')}>
      {label}
    </span>
  )
}

function ruleAction(rule: Rule): string {
  if (rule.action) return rule.action.toUpperCase()
  if (rule.category === 'CAT1') return 'BLOCK'
  if (rule.category?.startsWith('CAT3')) return 'ESCALATE'
  return 'VALIDATE'
}

function ruleSummary(rule: Rule): string {
  const existing = (rule.summary || '').trim()
  if (existing) return existing
  if (rule.description) {
    return `${rule.description} Action: ${ruleAction(rule)}${rule.attack_pattern ? ` · covers ${rule.attack_pattern}` : ''}.`
  }
  const bits = [`${rule.name} is a ${rule.category} ${rule.protocol} rule`, `action ${ruleAction(rule)}`]
  if (rule.rule_id) bits.push(`id ${rule.rule_id}`)
  if (rule.sid) bits.push(`sid ${rule.sid}`)
  return bits.join('; ') + '.'
}

function operatorInitials(name: string): string {
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((p) => p[0] || '')
    .join('')
    .toUpperCase()
}

function eventPeer(e: Pick<TrafficEvent, 'source' | 'global_title' | 'origin_realm'>): string {
  return e.source || e.global_title || e.origin_realm || '—'
}

function humanizeSignal(raw: string): string {
  const text = (raw || '').trim()
  if (!text) return 'Signaling event'
  return text
    .replace(/^TEL-(?:GTP|DIA|MAP|CAP|SS7)-/i, '')
    .replace(/[-_.]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function alertHeadline(a: Alert): string {
  const desc = humanizeSignal(a.description || '')
  if (desc && desc.toLowerCase() !== 'signaling event') return desc
  if (a.title && !/^CAT\d/i.test(a.title)) return a.title
  return a.title || a.category || 'Alert'
}

function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="ids-empty ids-empty--rich ids-empty--hero">
      <div className="ss7-empty-hero" aria-hidden>
        <div className="ss7-empty-hero__rings" />
        <div className="ss7-empty-hero__glyph">
          <IconShield />
        </div>
      </div>
      <strong>{title}</strong>
      {hint ? <span>{hint}</span> : null}
      {action}
    </div>
  )
}

function MetaChip({ label, value }: { label: string; value?: string | number | null }) {
  if (value == null || value === '' || value === '—') return null
  return (
    <span className="ids-meta-chip">
      <em>{label}</em>
      <code>{value}</code>
    </span>
  )
}

/* ---------- Threat feed ---------- */

function ThreatFeed({
  alerts,
  traffic,
  onViewAll,
  onSelectEvent,
}: {
  alerts: Alert[]
  traffic: TrafficEvent[]
  onViewAll: () => void
  onSelectEvent?: (event: TrafficEvent) => void
}) {
  const rows = useMemo(() => {
    type FeedRow = {
      id: string
      time: string
      category: string
      decision: string
      severity: string
      title: string
      protocol: string
      peer: string
      rule?: string
      subscriber?: string
      event?: TrafficEvent
    }
    const alertRows: FeedRow[] = alerts.slice(0, 12).map((a) => {
      const linked = traffic.find((t) => t.event_id === a.packet_event_id || t.rule_id === a.detection_rule)
      return {
        id: a.alert_id,
        time: a.timestamp,
        category: a.category || 'SYSTEM',
        decision: a.decision || '—',
        severity: (a.severity || 'info').toLowerCase(),
        title: alertHeadline(a),
        protocol: linked?.protocol || '',
        peer: linked ? eventPeer(linked) : a.subscriber_id_masked || '—',
        rule: a.detection_rule || linked?.rule_id,
        subscriber: a.subscriber_id_masked || linked?.subscriber_id_masked,
        event: linked,
      }
    })
    const trafficRows: FeedRow[] = traffic
      .filter((e) => e.decision === 'BLOCK' || e.decision === 'ESCALATE' || e.decision === 'ALLOW')
      .slice(0, 12)
      .map((e) => ({
        id: e.event_id,
        time: e.timestamp,
        category: e.category || 'SYSTEM',
        decision: e.decision || '—',
        severity: e.decision === 'BLOCK' ? 'critical' : e.decision === 'ESCALATE' ? 'medium' : 'low',
        title: humanizeSignal(e.procedure || e.protocol),
        protocol: e.protocol,
        peer: eventPeer(e),
        rule: e.rule_id,
        subscriber: e.subscriber_id_masked,
        event: e,
      }))
    const seen = new Set<string>()
    return [...alertRows, ...trafficRows]
      .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime())
      .filter((r) => {
        const key = `${r.rule || ''}|${r.peer}|${r.decision}|${r.title}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
      })
      .slice(0, 10)
  }, [alerts, traffic])

  return (
    <div className="ids-panel">
      <div className="ids-panel__head">
        <h3 className="ids-panel__title">Recent Decisions</h3>
        <button type="button" className="ids-panel__link" onClick={onViewAll}>
          All alerts →
        </button>
      </div>
      <div className="ids-panel__body">
        {rows.length === 0 ? (
          <EmptyState
            title="No decisions yet"
            hint="Live BLOCK / ESCALATE / ALLOW outcomes appear here as traffic is inspected."
          />
        ) : (
          <div className="ids-signal-list">
            {rows.map((r) => (
              <button
                key={r.id}
                type="button"
                className={classNames('ids-signal', `ids-signal--${r.severity}`, r.event && 'ids-signal--clickable')}
                onClick={() => r.event && onSelectEvent?.(r.event)}
              >
                <span className="ids-signal__rail" aria-hidden />
                <div className="ids-signal__top">
                  <StatusBadge status={r.decision} />
                  <StatusBadge status={r.category.startsWith('CAT3') ? 'CAT3' : r.category} />
                  {r.protocol ? <span className="ids-signal__proto">{r.protocol}</span> : null}
                  <span className="ids-signal__when" title={formatTime(r.time)}>
                    {formatRelative(r.time)}
                  </span>
                </div>
                <div className="ids-signal__title">{r.title}</div>
                <div className="ids-signal__meta">
                  <MetaChip label="Peer" value={r.peer} />
                  <MetaChip label="Rule" value={r.rule} />
                  <MetaChip label="IMSI" value={r.subscriber} />
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

type ThreatCatFilter = 'all' | 'LIVE' | 'CAT1' | 'CAT2' | 'CAT3'

type KpiTone = 'cyan' | 'violet' | 'amber' | 'danger' | 'blue' | 'success'

const KPI_COLOR: Record<KpiTone, string> = {
  cyan: '#22D3EE',
  violet: '#A855F7',
  amber: '#F5A524',
  danger: '#F43F5E',
  blue: '#3B82F6',
  success: '#10D9A0',
}

function KpiSpark({ color, seed }: { color: string; seed: number }) {
  const coords = Array.from({ length: 8 }, (_, i) => {
    const y = 20 - ((Math.abs(seed) * (i + 2) * 13) % 15)
    return [i * 16, y] as const
  })
  const points = coords.map(([x, y]) => `${x},${y}`).join(' ')
  const area = `0,28 ${points} 112,28`
  const gid = `spark-${Math.abs(seed) % 9973}-${color.replace('#', '')}`
  return (
    <svg className="ti-kpi__sparkline" viewBox="0 0 112 28" preserveAspectRatio="none" aria-hidden>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#${gid})`} className="ti-kpi__spark-fill" />
      <polyline
        className="ti-kpi__spark-line"
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="1.8"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <circle
        className="ti-kpi__spark-dot"
        cx={coords[coords.length - 1][0]}
        cy={coords[coords.length - 1][1]}
        r="2.2"
        fill={color}
      />
    </svg>
  )
}

function ThreatKpiCard({
  label,
  value,
  hint,
  tone = 'cyan',
  icon,
}: {
  label: string
  value: number | string
  tone?: KpiTone
  hint?: string
  icon?: ReactNode
}) {
  const color = KPI_COLOR[tone]
  const numeric = typeof value === 'number' ? value : Number.parseFloat(String(value)) || label.length
  return (
    <div className={`ti-kpi ti-kpi--ideal ti-kpi--${tone}`}>
      <span className="ti-kpi__rail" style={{ background: color }} aria-hidden />
      <span className="ti-kpi__icon" style={{ color, background: `${color}22`, boxShadow: `0 0 12px ${color}40` }}>
        {icon || <IconPulse />}
      </span>
      <div className="ti-kpi__meta">
        <strong className="ti-kpi__value">{typeof value === 'number' ? value.toLocaleString() : value}</strong>
        <span className="ti-kpi__label">{label}</span>
        {hint ? <span className="ti-kpi__hint">{hint}</span> : null}
      </div>
      <div className="ti-kpi__spark-wrap">
        <KpiSpark color={color} seed={numeric + label.length} />
      </div>
    </div>
  )
}

function ThreatActors({
  alerts,
  traffic,
}: {
  alerts: Alert[]
  traffic: TrafficEvent[]
}) {
  const actors = useMemo(() => {
    type Agg = { name: string; blocks: number; escalations: number; protocols: Set<string> }
    const map = new Map<string, Agg>()
    const bump = (name: string, kind: 'BLOCK' | 'ESCALATE', protocol?: string) => {
      const key = name || 'unknown'
      const cur = map.get(key) || { name: key, blocks: 0, escalations: 0, protocols: new Set<string>() }
      if (kind === 'BLOCK') cur.blocks += 1
      else cur.escalations += 1
      if (protocol) cur.protocols.add(protocol)
      map.set(key, cur)
    }
    for (const t of traffic) {
      if (t.decision !== 'BLOCK' && t.decision !== 'ESCALATE') continue
      bump(eventPeer(t), t.decision, t.protocol)
    }
    for (const a of alerts) {
      if (a.decision !== 'BLOCK' && a.decision !== 'ESCALATE') continue
      const linked = traffic.find((t) => t.event_id === a.packet_event_id)
      bump(linked ? eventPeer(linked) : a.subscriber_id_masked || a.category, a.decision as 'BLOCK' | 'ESCALATE', linked?.protocol)
    }
    return [...map.values()]
      .map((a) => ({
        ...a,
        score: a.blocks * 3 + a.escalations * 2,
        protocol: [...a.protocols].slice(0, 2).join('/') || '—',
      }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 6)
  }, [alerts, traffic])

  const max = Math.max(1, ...actors.map((a) => a.score))

  return (
    <div className="ids-panel ti-actors">
      <div className="ids-panel__head">
        <h3 className="ids-panel__title">Top Sources</h3>
      </div>
      <div className="ids-panel__body ti-actors__body">
        {actors.map((a, i) => {
          const tone = ['#22D3EE', '#3B82F6', '#A855F7', '#F5A524', '#10D9A0', '#F43F5E'][i % 6]
          const hits = a.blocks + a.escalations
          const share = Math.max(0.1, (a.score / max) * 100)
          return (
            <div key={a.name} className="ti-source">
              <div className="ti-source__row">
                <strong title={a.name}>
                  #{i + 1} {a.name.length > 22 ? `${a.name.slice(0, 20)}…` : a.name}
                </strong>
                <span>
                  {hits} hit{hits === 1 ? '' : 's'}
                </span>
              </div>
              <div className="ti-source__bar">
                <div className="ti-source__fill" style={{ width: `${share}%`, background: tone, boxShadow: `0 0 8px ${tone}` }} />
              </div>
              <span className="ti-source__share">{share.toFixed(1)}% share</span>
            </div>
          )
        })}
        {actors.length === 0 && (
          <EmptyState title="No hostile sources" hint="Peers with BLOCK or ESCALATE decisions rank here." />
        )}
      </div>
    </div>
  )
}

function ActiveThreatsTable({
  alerts,
  traffic,
  catFilter,
  onAck,
  onInvestigate,
}: {
  alerts: Alert[]
  traffic: TrafficEvent[]
  catFilter: ThreatCatFilter
  onAck: (id: string) => void
  onInvestigate: (target: { event?: TrafficEvent | null; alertId?: string; ruleId?: string }) => void
}) {
  const rows = useMemo(() => {
    type ThreatRow = {
      id: string
      time: string
      severity: string
      category: string
      title: string
      protocol: string
      peer: string
      rule?: string
      decision: string
      ack: boolean
      kind: 'alert' | 'traffic'
      event?: TrafficEvent
    }
    const fromAlerts: ThreatRow[] = alerts.map((a) => {
      const linked = traffic.find((t) => t.event_id === a.packet_event_id)
      return {
        id: a.alert_id,
        time: a.timestamp,
        severity: (a.severity || 'info').toLowerCase(),
        category: a.category || '',
        title: alertHeadline(a),
        protocol: linked?.protocol || '—',
        peer: linked ? eventPeer(linked) : a.subscriber_id_masked || '—',
        rule: a.detection_rule || linked?.rule_id,
        decision: a.decision,
        ack: a.acknowledged,
        kind: 'alert',
        event: linked,
      }
    })
    const fromTraffic: ThreatRow[] = traffic
      .filter((t) => t.decision === 'BLOCK' || t.decision === 'ESCALATE')
      .map((t) => ({
        id: t.event_id,
        time: t.timestamp,
        severity: t.decision === 'BLOCK' ? 'critical' : 'medium',
        category: t.category || '',
        title: humanizeSignal(t.procedure || t.protocol),
        protocol: t.protocol || '—',
        peer: eventPeer(t),
        rule: t.rule_id,
        decision: t.decision,
        ack: false,
        kind: 'traffic',
        event: t,
      }))
    const seen = new Set<string>()
    let out = [...fromAlerts, ...fromTraffic]
      .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime())
      .filter((r) => {
        const key = `${r.kind}:${r.id}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
      })
    if (catFilter === 'CAT1') out = out.filter((r) => r.category === 'CAT1')
    if (catFilter === 'CAT2') out = out.filter((r) => r.category === 'CAT2')
    if (catFilter === 'CAT3') out = out.filter((r) => r.category.startsWith('CAT3'))
    if (catFilter === 'LIVE') out = out.filter((r) => !r.ack).slice(0, 12)
    return out.slice(0, 14)
  }, [alerts, traffic, catFilter])

  const exportCsv = () => {
    const header = ['when', 'decision', 'category', 'signal', 'protocol', 'peer', 'rule']
    const lines = [
      header.join(','),
      ...rows.map((r) =>
        [r.time, r.decision, r.category, r.title, r.protocol, r.peer, r.rule || '']
          .map((cell) => `"${String(cell).replace(/"/g, '""')}"`)
          .join(','),
      ),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'active-threats.csv'
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="ids-panel ti-table-panel">
      <div className="ids-panel__head">
        <div className="ti-panel-title">
          <span className="ti-ping" aria-hidden />
          <h3 className="ids-panel__title">Active Threats</h3>
          <span className="ti-count-pill">{rows.length} active</span>
        </div>
        <div className="ti-panel-tools">
          <span className="ti-filter-pill">Filter: {catFilter === 'all' ? 'All Categories' : catFilter}</span>
          <button type="button" className="ti-export" onClick={exportCsv}>
            Export CSV
          </button>
        </div>
      </div>
      <div className="ids-panel__body ti-table-wrap">
        <table className="ti-table">
          <thead>
            <tr>
              <th>When</th>
              <th>Decision</th>
              <th>Signal</th>
              <th>Peer</th>
              <th>Rule</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.kind}-${r.id}`} className={classNames(r.ack && 'ti-table__row--muted')}>
                <td className="ti-table__time" title={formatTime(r.time)}>
                  {formatUtcClock(r.time)}
                </td>
                <td>
                  <div className="ti-table__stack">
                    <StatusBadge status={r.decision} />
                    <span className={classNames('ti-sev', `ti-sev--${r.severity}`, r.category.startsWith('CAT3') && 'ti-sev--cat3')}>
                      {r.category.startsWith('CAT3') ? 'CAT3' : r.category || r.severity}
                    </span>
                  </div>
                </td>
                <td>
                  <div className="ti-table__signal">
                    <strong>{r.title}</strong>
                    <span>{r.protocol}</span>
                  </div>
                </td>
                <td className="ti-table__peer">{r.peer}</td>
                <td className="ti-table__rule">{r.rule || '—'}</td>
                <td className="ti-table__actions">
                  <button
                    type="button"
                    className="ti-act"
                    onClick={() =>
                      onInvestigate({
                        event: r.event || null,
                        alertId: r.kind === 'alert' ? r.id : undefined,
                        ruleId: r.rule,
                      })
                    }
                  >
                    Investigate
                  </button>
                  {r.kind === 'alert' && !r.ack && (
                    <button type="button" className="ti-act ti-act--ghost" onClick={() => onAck(r.id)}>
                      Ack
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    title="No threats in this scope"
                    hint="Open LIVE or clear the CAT filter when new blocks and escalations arrive."
                  />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ExploitationTrends({ metrics }: { metrics: IDSMetrics | null }) {
  const data = useMemo(
    () => [
      { name: 'CAT1', value: metrics?.cat1_matches || 0, fill: CHART_COLORS.cyan },
      { name: 'CAT2', value: metrics?.cat2_blocks || 0, fill: CHART_COLORS.purple },
      { name: 'CAT3', value: metrics?.cat3_escalations || 0, fill: CHART_COLORS.amber },
      { name: 'Blocked', value: metrics?.packets_blocked || 0, fill: CHART_COLORS.blue },
    ],
    [metrics],
  )

  return (
    <div className="ids-panel ti-trends">
      <div className="ids-panel__head">
        <h3 className="ids-panel__title">Category Enforcement</h3>
        <span className="ids-panel__aside">Last 24 hours</span>
      </div>
      <div className="ids-panel__body">
        {!metrics ? (
          <div className="ids-empty">IDS status unavailable.</div>
        ) : (
          <div className="ti-trends__chart">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={data} margin={{ top: 12, right: 12, left: 0, bottom: 4 }}>
                <CartesianGrid stroke={CHART_GRID} vertical={false} strokeDasharray="3 6" />
                <XAxis dataKey="name" tick={CHART_TICK} axisLine={false} tickLine={false} />
                <YAxis tick={CHART_TICK} axisLine={false} tickLine={false} allowDecimals={false} width={36} />
                <Tooltip
                  cursor={{ fill: 'rgba(34, 211, 238, 0.06)' }}
                  contentStyle={CHART_TOOLTIP}
                  labelStyle={{ color: '#9DB2D6', marginBottom: 4 }}
                  itemStyle={{ color: '#F1F6FF' }}
                />
                <Bar dataKey="value" name="Events" radius={[4, 4, 0, 0]} maxBarSize={44}>
                  {data.map((d) => (
                    <Cell key={d.name} fill={d.fill} />
                  ))}
                </Bar>
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  )
}

function IocFeed({ alerts, traffic }: { alerts: Alert[]; traffic: TrafficEvent[] }) {
  const iocs = useMemo(() => {
    type Ioc = { id: string; severity: string; kind: string; label: string; context: string; time: string }
    const out: Ioc[] = []
    const push = (ioc: Ioc) => {
      if (out.some((x) => x.kind === ioc.kind && x.label === ioc.label)) return
      out.push(ioc)
    }
    for (const a of alerts.slice(0, 20)) {
      if (a.detection_rule) {
        push({
          id: `${a.alert_id}-rule`,
          severity: (a.severity || 'info').toLowerCase(),
          kind: 'rule',
          label: a.detection_rule,
          context: `${a.decision} · ${alertHeadline(a)}`,
          time: a.timestamp,
        })
      }
      if (a.subscriber_id_masked) {
        push({
          id: `${a.alert_id}-imsi`,
          severity: (a.severity || 'info').toLowerCase(),
          kind: 'imsi',
          label: a.subscriber_id_masked,
          context: `${a.category} · ${a.decision}`,
          time: a.timestamp,
        })
      }
    }
    for (const t of traffic.filter((e) => e.decision === 'BLOCK' || e.decision === 'ESCALATE').slice(0, 20)) {
      const peer = eventPeer(t)
      if (peer && peer !== '—') {
        push({
          id: `${t.event_id}-peer`,
          severity: t.decision === 'BLOCK' ? 'critical' : 'medium',
          kind: t.origin_realm ? 'realm' : 'peer',
          label: peer,
          context: `${t.decision} · ${t.protocol || 'sig'} · ${humanizeSignal(t.procedure || '')}`,
          time: t.timestamp,
        })
      }
      if (t.rule_id) {
        push({
          id: `${t.event_id}-rule`,
          severity: t.decision === 'BLOCK' ? 'critical' : 'medium',
          kind: 'rule',
          label: t.rule_id,
          context: `${t.decision} · ${t.protocol || 'sig'}`,
          time: t.timestamp,
        })
      }
    }
    return out.slice(0, 12)
  }, [alerts, traffic])

  return (
    <div className="ids-panel ti-ioc">
      <div className="ids-panel__head">
        <h3 className="ids-panel__title">Indicators</h3>
        <span className="ids-panel__count">{iocs.length}</span>
      </div>
      <div className="ids-panel__body ti-ioc__body">
        {iocs.map((ioc) => (
          <div key={ioc.id} className={classNames('ti-ind', `ti-ind--${ioc.kind}`)}>
            <span className="ti-ind__kind">{titleCaseKind(ioc.kind)}</span>
            <code className="ti-ind__code">{ioc.label}</code>
          </div>
        ))}
        {iocs.length === 0 && (
          <EmptyState title="No indicators yet" hint="Rule IDs, realms, and IMSIs from live blocks show up here." />
        )}
      </div>
    </div>
  )
}

function SignalingStream({ traffic }: { traffic: TrafficEvent[] }) {
  const rows = traffic.slice(0, 8)
  return (
    <section className="ids-panel ti-stream ti-stream--live ti-stream--ideal">
      <div className="ids-panel__head">
        <div className="ti-panel-title">
          <h3 className="ids-panel__title">Live Traffic</h3>
          <span className="ids-panel__aside">Live stream</span>
        </div>
      </div>
      <div className="ids-panel__body ti-table-wrap">
        <table className="ti-table">
          <thead>
            <tr>
              <th>When</th>
              <th>Protocol</th>
              <th>Signal</th>
              <th>Peer</th>
              <th>Destination</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.event_id}>
                <td className="ti-table__time">{formatUtcClock(e.timestamp)}</td>
                <td className="ti-table__rule">{e.protocol || '—'}</td>
                <td>
                  <div className="ti-table__signal">
                    <strong>{humanizeSignal(e.procedure || e.protocol)}</strong>
                    <span>{e.category || '—'}</span>
                  </div>
                </td>
                <td className="ti-table__peer">{eventPeer(e)}</td>
                <td className="ti-table__peer">{e.destination || '—'}</td>
                <td>
                  <StatusBadge status={e.decision || 'ALLOW'} />
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState title="No signaling yet" hint="Live ingress appears here as packets are inspected." />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function ThreatIntelBoard({
  metrics,
  alerts,
  traffic,
  onAck,
  onInvestigate,
  onViewAlerts,
}: {
  metrics: IDSMetrics | null
  alerts: Alert[]
  traffic: TrafficEvent[]
  onAck: (id: string) => void
  onInvestigate: (target: { event?: TrafficEvent | null; alertId?: string; ruleId?: string }) => void
  onViewAlerts: () => void
}) {
  const [catFilter, setCatFilter] = useState<ThreatCatFilter>('LIVE')
  const openAlerts = alerts.filter((a) => !a.acknowledged).length
  const threatScore = Math.min(99, (metrics?.packets_blocked || 0) * 3 + (metrics?.cat1_matches || 0) * 5)

  return (
    <div className="ti-board ti-board--live">
      <div className="ti-filters">
        <div className="ti-filters__group">
          <span className="ti-filters__label">Scope</span>
          {(['LIVE', 'CAT1', 'CAT2', 'CAT3'] as const).map((f) => (
            <button
              key={f}
              type="button"
              className={classNames('ti-chip', `ti-chip--${f.toLowerCase()}`, catFilter === f && 'ti-chip--active')}
              onClick={() => setCatFilter(catFilter === f ? 'all' : f)}
            >
              {f}
            </button>
          ))}
        </div>
        <button type="button" className="ids-panel__link" onClick={onViewAlerts}>
          Open alerts →
        </button>
      </div>

      <div className="ti-kpi-row">
        <ThreatKpiCard label="Threat Score" value={threatScore} tone="cyan" hint="from live blocks" icon={<IconShield />} />
        <ThreatKpiCard label="Open Alerts" value={openAlerts} tone="blue" hint="unacknowledged" icon={<IconBell />} />
        <ThreatKpiCard label="Blocked" value={metrics?.packets_blocked || 0} tone="danger" hint="packets" icon={<IconBlock />} />
        <ThreatKpiCard label="CAT1" value={metrics?.cat1_matches || 0} tone="cyan" hint="critical hits" icon={<IconPulse />} />
        <ThreatKpiCard label="CAT2" value={metrics?.cat2_blocks || 0} tone="violet" hint="IR.21 blocks" icon={<IconInspect />} />
        <ThreatKpiCard label="CAT3" value={metrics?.cat3_escalations || 0} tone="amber" hint="escalations" icon={<IconWarn />} />
      </div>

      <div className="ti-main">
        <ActiveThreatsTable
          alerts={alerts}
          traffic={traffic}
          catFilter={catFilter}
          onAck={onAck}
          onInvestigate={onInvestigate}
        />
        <div className="ti-side">
          <ThreatActors alerts={alerts} traffic={traffic} />
          <IocFeed alerts={alerts} traffic={traffic} />
        </div>
      </div>

      <div className="ti-bottom ti-bottom--single">
        <ExploitationTrends metrics={metrics} />
        <TrafficComposition metrics={metrics} />
      </div>
      <SignalingStream traffic={traffic} />
    </div>
  )
}

/* ---------- Composition donut ---------- */

function TrafficComposition({ metrics }: { metrics: IDSMetrics | null }) {
  const allowed = metrics?.packets_allowed || 0
  const blocked = metrics?.packets_blocked || 0
  const escalated = metrics?.packets_escalated || 0
  const other = Math.max(0, (metrics?.packets_inspected || 0) - allowed - blocked - escalated)
  const total = Math.max(1, allowed + blocked + escalated + other)
  const data = [
    { name: 'Allowed', value: allowed, color: CHART_COLORS.green },
    { name: 'Other', value: other, color: CHART_COLORS.blue },
    { name: 'Escalated', value: escalated, color: CHART_COLORS.amber },
    { name: 'Blocked', value: blocked, color: CHART_COLORS.red },
  ]

  return (
    <div className="ids-panel">
      <div className="ids-panel__head">
        <h3 className="ids-panel__title">Traffic Composition</h3>
        <span className="ids-panel__aside">Live stream</span>
      </div>
      <div className="ids-panel__body">
        {!metrics ? (
          <div className="ids-empty">IDS status unavailable.</div>
        ) : (
        <div className="ids-compose">
          <div className="ids-compose__chart">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  dataKey="value"
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={3}
                  stroke="rgba(5, 11, 26, 0.9)"
                  strokeWidth={2}
                >
                  {data.map((d) => (
                    <Cell key={d.name} fill={d.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={CHART_TOOLTIP}
                  labelStyle={{ color: '#9DB2D6' }}
                  itemStyle={{ color: '#F1F6FF' }}
                  formatter={(value: number, name: string) => [
                    `${Number(value).toLocaleString()} (${((Number(value) / total) * 100).toFixed(1)}%)`,
                    name,
                  ]}
                />
                <text x="50%" y="46%" textAnchor="middle" fill="#5F7699" fontSize="10" letterSpacing="1.2" fontFamily="Outfit, system-ui, sans-serif">
                  TOTAL
                </text>
                <text x="50%" y="58%" textAnchor="middle" fill="#F1F6FF" fontSize="17" fontWeight="650" fontFamily="JetBrains Mono, monospace">
                  {(metrics.packets_inspected || 0).toLocaleString()}
                </text>
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="ids-compose__legend">
            {data.map((d) => (
              <div key={d.name} className="ids-compose__item">
                <span className="ids-compose__swatch" style={{ background: d.color }} />
                <span>{d.name}</span>
                <span className="ids-compose__val">{((d.value / total) * 100).toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>
        )}
      </div>
    </div>
  )
}

/* ---------- Analytics chart ---------- */

function SecondaryAnalytics({ metrics }: { metrics: IDSMetrics | null }) {
  const data = useMemo(
    () => [
      { name: 'Inspected', value: metrics?.packets_inspected || 0, fill: CHART_COLORS.cyan },
      { name: 'Allowed', value: metrics?.packets_allowed || 0, fill: CHART_COLORS.green },
      { name: 'Blocked', value: metrics?.packets_blocked || 0, fill: CHART_COLORS.red },
      { name: 'Escalated', value: metrics?.packets_escalated || 0, fill: CHART_COLORS.amber },
    ],
    [metrics],
  )

  return (
    <div className="ids-panel ids-analytics">
      <div className="ids-panel__head">
        <h3 className="ids-panel__title">Signaling Volume & Enforcement</h3>
        <span className="ids-panel__aside">Live stream</span>
      </div>
      <div className="ids-panel__body">
        {!metrics ? (
          <div className="ids-empty">IDS status unavailable.</div>
        ) : (
          <div className="ids-analytics__chart">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={data} margin={{ top: 12, right: 12, left: 0, bottom: 4 }}>
                <CartesianGrid stroke={CHART_GRID} vertical={false} strokeDasharray="3 6" />
                <XAxis dataKey="name" tick={CHART_TICK} axisLine={false} tickLine={false} />
                <YAxis tick={CHART_TICK} axisLine={false} tickLine={false} allowDecimals={false} width={40} />
                <Tooltip
                  cursor={{ fill: 'rgba(34, 211, 238, 0.06)' }}
                  contentStyle={CHART_TOOLTIP}
                  labelStyle={{ color: '#9DB2D6', marginBottom: 4 }}
                  itemStyle={{ color: '#F1F6FF' }}
                />
                <Bar dataKey="value" name="Packets" radius={[4, 4, 0, 0]} maxBarSize={48}>
                  {data.map((d) => (
                    <Cell key={d.name} fill={d.fill} />
                  ))}
                </Bar>
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  )
}

/* ---------- Partners ---------- */

function PartnerTable({
  partners,
  query,
  onSelect,
}: {
  partners: Partner[]
  query: string
  onSelect: (p: Partner) => void
}) {
  const [expanded, setExpanded] = useState<string | null>(null)
  const filtered = partners.filter((p) => {
    const q = query.trim().toLowerCase()
    if (!q) return true
    return [p.operator_name, p.country, p.tadig_code, p.mcc, p.mnc, p.diameter?.origin_realm]
      .join(' ')
      .toLowerCase()
      .includes(q)
  })

  return (
    <div className="ids-ptable-wrap">
      <table className="ids-ptable">
        <thead>
          <tr>
            <th>Operator</th>
            <th>Code</th>
            <th>Status</th>
            <th>Country</th>
            <th>Diameter / LTE</th>
            <th>GTP / Packet</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((p) => {
            const open = expanded === p.partner_id
            return (
              <Fragment key={p.partner_id}>
                <tr
                  className={classNames('ids-ptable__row', open && 'ids-ptable__row--open')}
                  onClick={() => setExpanded(open ? null : p.partner_id)}
                >
                  <td>
                    <div className="ids-op">
                      <span className="ids-op__avatar">{operatorInitials(p.operator_name)}</span>
                      <div>
                        <div className="ids-op__name">{p.operator_name}</div>
                        <div className="ids-op__code">
                          MCC/MNC {p.mcc}-{p.mnc}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{p.tadig_code}</td>
                  <td>
                    <StatusBadge status={(p.agreement_status || 'ACTIVE').toUpperCase()} />
                  </td>
                  <td>{p.country}</td>
                  <td>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                      {p.diameter?.origin_realm || '—'}
                      <div style={{ color: 'var(--text-muted)' }}>
                        LTE {p.diameter?.lte_roaming ? 'yes' : 'no'}
                      </div>
                    </div>
                  </td>
                  <td>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                      {(p.gtp?.allowed_apns || []).slice(0, 2).join(', ') || '—'}
                      <div style={{ color: 'var(--text-muted)' }}>{p.gtp?.gtp_version || '—'}</div>
                    </div>
                  </td>
                  <td>
                    <div className="ids-row-actions" onClick={(e) => e.stopPropagation()}>
                      <button type="button" className="ids-icon-btn" title="Details" onClick={() => onSelect(p)}>
                        <IconInspect />
                      </button>
                      <button type="button" className="ids-icon-btn" title="Analytics">
                        <IconPulse />
                      </button>
                    </div>
                  </td>
                </tr>
                {open && (
                  <tr className="ids-expand">
                    <td colSpan={7}>
                      <div className="ids-expand__grid">
                        <div className="ids-expand__card">
                          <h5>SS7 / MAP / CAP</h5>
                          <dl>
                            <dt>GT</dt>
                            <dd>{(p.ss7?.gt_prefixes || []).join(', ') || '—'}</dd>
                            <dt>MAP</dt>
                            <dd>{(p.ss7?.map_versions || []).join(', ') || '—'}</dd>
                            <dt>CAP</dt>
                            <dd>{(p.ss7?.cap_versions || []).join(', ') || '—'}</dd>
                          </dl>
                        </div>
                        <div className="ids-expand__card">
                          <h5>Diameter / LTE</h5>
                          <dl>
                            <dt>Realm</dt>
                            <dd>{p.diameter?.origin_realm || '—'}</dd>
                            <dt>Apps</dt>
                            <dd>{(p.diameter?.diameter_applications || []).join(', ') || '—'}</dd>
                            <dt>LTE roaming</dt>
                            <dd>{p.diameter?.lte_roaming ? 'yes' : 'no'}</dd>
                          </dl>
                        </div>
                        <div className="ids-expand__card">
                          <h5>GTP / Packet</h5>
                          <dl>
                            <dt>APN</dt>
                            <dd>{(p.gtp?.allowed_apns || []).join(', ') || '—'}</dd>
                            <dt>GTP</dt>
                            <dd>{p.gtp?.gtp_version || '—'}</dd>
                            <dt>Data roaming</dt>
                            <dd>{p.gtp?.data_roaming ? 'yes' : 'no'}</dd>
                          </dl>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={7}>
                <div className="ids-empty">No partners match this filter.</div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function PartnerDrawer({ partner, onClose }: { partner: Partner | null; onClose: () => void }) {
  if (!partner) return null
  return (
    <div className="ids-drawer">
      <div className="ids-drawer__overlay" onClick={onClose} />
      <div className="ids-drawer__panel">
        <div className="ids-drawer__header">
          <div>
            <h3>{partner.operator_name}</h3>
            <div style={{ marginTop: 6, display: 'flex', gap: 8, alignItems: 'center' }}>
              <StatusBadge status={(partner.agreement_status || 'ONLINE').toUpperCase()} pulse />
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                {partner.country} · IR.21 {partner.tadig_code}
              </span>
            </div>
          </div>
          <button type="button" className="ids-drawer__close" onClick={onClose} aria-label="Close">
            <IconClose />
          </button>
        </div>
        <div className="ids-drawer__content">
          <div className="ids-drawer__section">
            <h4>Signaling Stack</h4>
            <dl className="ids-drawer__dl">
              <dt>GT prefixes</dt>
              <dd>{(partner.ss7?.gt_prefixes || []).join(', ') || '—'}</dd>
              <dt>MAP</dt>
              <dd>{(partner.ss7?.map_versions || []).join(', ') || '—'}</dd>
              <dt>CAP</dt>
              <dd>{(partner.ss7?.cap_versions || []).join(', ') || '—'}</dd>
            </dl>
          </div>
          <div className="ids-drawer__section">
            <h4>Diameter / LTE</h4>
            <dl className="ids-drawer__dl">
              <dt>Realm</dt>
              <dd>{partner.diameter?.origin_realm || '—'}</dd>
              <dt>Hosts</dt>
              <dd>{(partner.diameter?.origin_hosts || []).join(', ') || '—'}</dd>
              <dt>Apps</dt>
              <dd>{(partner.diameter?.diameter_applications || []).join(', ') || '—'}</dd>
              <dt>LTE roaming</dt>
              <dd>{partner.diameter?.lte_roaming ? 'yes' : 'no'}</dd>
            </dl>
          </div>
          <div className="ids-drawer__section">
            <h4>GTP</h4>
            <dl className="ids-drawer__dl">
              <dt>APNs</dt>
              <dd>{(partner.gtp?.allowed_apns || []).join(', ') || '—'}</dd>
              <dt>Version</dt>
              <dd>{partner.gtp?.gtp_version || '—'}</dd>
              <dt>Data roaming</dt>
              <dd>{partner.gtp?.data_roaming ? 'yes' : 'no'}</dd>
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ---------- Investigate drawer ---------- */

function EvidenceList({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null
  return (
    <div className="ids-why__block">
      <h5>{title}</h5>
      <ul>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  )
}

function InvestigateDrawer({
  event,
  brief,
  loading,
  error,
  onClose,
}: {
  event: TrafficEvent | null
  brief: InvestigationBrief | null
  loading: boolean
  error: string | null
  onClose: () => void
}) {
  if (!event && !brief && !loading) return null

  const decision = brief?.decision || event?.decision || '—'
  const category = brief?.category || event?.category || '—'
  const ir = brief?.ir_evidence
  const sub = brief?.subscriber_analysis
  const validation = brief?.validation
  const whyTitle =
    decision === 'BLOCK' ? 'Why it was blocked' : decision === 'ESCALATE' ? 'Why it was escalated' : 'Why this decision'

  const validationItems: string[] = []
  if (validation) {
    if (validation.authorized_procedure === false) validationItems.push('Procedure is not authorized for this direction')
    if (validation.partner_found_in_ir21 === false) validationItems.push('Peer not found in IR.21 roaming agreements')
    if (validation.parameters_consistent === false) validationItems.push('Observed parameters are inconsistent with IR.21')
    if (Array.isArray(validation.checks)) {
      for (const check of validation.checks) {
        if (typeof check === 'string') validationItems.push(check)
        else if (check && typeof check === 'object') {
          const stage = (check as { stage?: string; reason?: string; status?: string }).stage
          const reason = (check as { reason?: string }).reason
          const status = (check as { status?: string }).status
          validationItems.push([stage, status, reason].filter(Boolean).join(' · '))
        }
      }
    }
  }

  const irItems: string[] = []
  if (ir?.partner_id) irItems.push(`Partner ${ir.partner_id}${ir.document ? ` · ${ir.document}` : ''}`)
  if (ir?.mismatches?.length) irItems.push(`Mismatches: ${ir.mismatches.join(', ')}`)
  if (ir?.matched_fields?.length) irItems.push(`Matched fields: ${ir.matched_fields.join(', ')}`)
  if (ir?.expected_values) {
    irItems.push(
      `Expected: ${Object.entries(ir.expected_values)
        .map(([k, v]) => `${k}=${String(v)}`)
        .join(', ')}`,
    )
  }
  if (ir?.observed_values) {
    irItems.push(
      `Observed: ${Object.entries(ir.observed_values)
        .map(([k, v]) => `${k}=${String(v)}`)
        .join(', ')}`,
    )
  }

  const travelItems: string[] = []
    if (sub) {
      if (sub.flags?.length) travelItems.push(`Flags: ${sub.flags.join(', ')}`)
      if (sub.distance_km != null && sub.delta_seconds != null) {
        travelItems.push(
          `${sub.distance_km.toFixed(1)} km in ${sub.delta_seconds.toFixed(0)}s` +
            (sub.required_velocity_kmh != null
              ? ` → ${sub.required_velocity_kmh.toFixed(0)} km/h (max ${sub.max_plausible_velocity_kmh ?? '—'})`
              : ''),
        )
      }
      const prev = sub.previous_location
      const curr = sub.current_location
      if (prev || curr) {
        const fmt = (loc?: Record<string, unknown>) => {
          if (!loc) return '—'
          if (loc.mcc_mnc) return String(loc.mcc_mnc)
          if (loc.latitude != null && loc.longitude != null) return `${loc.latitude}, ${loc.longitude}`
          return 'unknown'
        }
        travelItems.push(`Path ${fmt(prev)} → ${fmt(curr)}`)
      }
    }

  return (
    <div className="ids-drawer">
      <div className="ids-drawer__overlay" onClick={onClose} />
      <div className="ids-drawer__panel ids-drawer__panel--investigate">
        <div className="ids-drawer__header">
          <div>
            <h3>Investigate</h3>
            <div className="ids-drawer__subheader">
              <StatusBadge status={decision} />
              <StatusBadge status={category} />
              {event ? <span>{formatRelative(event.timestamp)}</span> : null}
            </div>
          </div>
          <button type="button" className="ids-drawer__close" onClick={onClose} aria-label="Close">
            <IconClose />
          </button>
        </div>
        <div className="ids-drawer__content">
          <div className="ids-why">
            <div className="ids-why__head">
              <h4>{whyTitle}</h4>
              {brief?.confidence != null ? (
                <span className="ids-why__conf">{Math.round(brief.confidence * 100)}% confidence</span>
              ) : null}
            </div>
            {loading ? <div className="ids-empty">Building investigation brief…</div> : null}
            {error ? <div className="ids-why__error">{error}</div> : null}
            {!loading && (
              <>
                <p className="ids-why__explanation">{brief?.explanation || 'Awaiting engine rationale.'}</p>
                {brief?.reason && brief.reason !== brief.explanation ? (
                  <p className="ids-why__reason">
                    <strong>Engine reason</strong>
                    {brief.reason}
                  </p>
                ) : null}
              </>
            )}
          </div>

          {event && (
            <div className="ids-drawer__section">
              <h4>Signal</h4>
              <dl className="ids-drawer__dl">
                <dt>What</dt>
                <dd>{humanizeSignal(event.procedure || event.protocol)}</dd>
                <dt>Protocol</dt>
                <dd>{event.protocol || '—'}</dd>
                <dt>Peer</dt>
                <dd>{eventPeer(event)}</dd>
                <dt>Destination</dt>
                <dd>{event.destination || '—'}</dd>
                <dt>Subscriber</dt>
                <dd>{event.subscriber_id_masked || brief?.subscriber_analysis?.subscriber_id_masked || '—'}</dd>
                <dt>Rule</dt>
                <dd>{brief?.detection_rule || event.rule_id || '—'}</dd>
                <dt>Latency</dt>
                <dd>{(event.processing_latency_ms || 0).toFixed(2)}ms</dd>
              </dl>
            </div>
          )}

          {brief?.rule && (
            <div className="ids-drawer__section">
              <h4>Matched Rule</h4>
              <dl className="ids-drawer__dl">
                <dt>ID</dt>
                <dd>{brief.rule.rule_id || brief.detection_rule}</dd>
                <dt>Name</dt>
                <dd>{brief.rule.name || '—'}</dd>
                <dt>Action</dt>
                <dd>{brief.rule.action || decision}</dd>
                {brief.attack_pattern ? (
                  <>
                    <dt>Pattern</dt>
                    <dd>{brief.attack_pattern}</dd>
                  </>
                ) : null}
                {brief.rule.description ? (
                  <>
                    <dt>Description</dt>
                    <dd>{brief.rule.description}</dd>
                  </>
                ) : null}
                {brief.rule.validation_logic ? (
                  <>
                    <dt>Logic</dt>
                    <dd className="ids-drawer__mono">{brief.rule.validation_logic}</dd>
                  </>
                ) : null}
                {brief.rule.reference ? (
                  <>
                    <dt>Reference</dt>
                    <dd>{brief.rule.reference}</dd>
                  </>
                ) : null}
              </dl>
            </div>
          )}

          {(validationItems.length > 0 || irItems.length > 0 || travelItems.length > 0) && (
            <div className="ids-drawer__section">
              <h4>Evidence</h4>
              <EvidenceList title="Validation checks" items={validationItems} />
              <EvidenceList title="IR.21 context" items={irItems} />
              <EvidenceList title="Subscriber analysis" items={travelItems} />
            </div>
          )}

          {brief?.enforcement && (
            <div className="ids-drawer__section">
              <h4>Enforcement</h4>
              <dl className="ids-drawer__dl">
                <dt>Mode</dt>
                <dd>{brief.enforcement}</dd>
                <dt>Dry run</dt>
                <dd>{brief.dry_run ? 'Yes' : 'No'}</dd>
              </dl>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

/* ---------- Rules ---------- */

function RuleRow({ rule, expanded, onToggle }: { rule: Rule; expanded: boolean; onToggle: () => void }) {
  const categoryClass =
    {
      CAT1: 'ids-rule--cat1',
      CAT2: 'ids-rule--cat2',
      'CAT3.1': 'ids-rule--cat3',
      'CAT3.2': 'ids-rule--cat3',
    }[rule.category] || ''
  const action = ruleAction(rule)
  const summary = ruleSummary(rule)

  return (
    <div className={classNames('ids-rule', categoryClass, expanded && 'ids-rule--open', !rule.enabled && 'ids-rule--disabled')}>
      <button type="button" className="ids-rule__row" onClick={onToggle} aria-expanded={expanded}>
        <span className="ids-rule__id" title={rule.rule_id}>
          {rule.rule_id}
        </span>
        <span className="ids-rule__cat">
          <StatusBadge status={rule.category} />
        </span>
        <span className="ids-rule__signal">
          <strong className="ids-rule__name">{rule.name}</strong>
          <span className="ids-rule__summary" title={summary}>
            {summary}
          </span>
        </span>
        <span className="ids-rule__proto">{rule.protocol || '—'}</span>
        <span className="ids-rule__gen">{rule.generation || '—'}</span>
        <span className={classNames('ids-rule__action', `ids-rule__action--${action.toLowerCase()}`)}>{action}</span>
        <span className={classNames('ids-rule__severity', `ids-rule__severity--${(rule.severity || '').toLowerCase()}`)}>
          {(rule.severity || '—').toString().toUpperCase()}
        </span>
        <span className="ids-rule__sid">{rule.sid != null ? rule.sid : '—'}</span>
        <span className="ids-rule__chev" aria-hidden>
          {expanded ? '▾' : '▸'}
        </span>
      </button>
      {expanded && (
        <div className="ids-rule__details">
          <div className="ids-rule__details-grid">
            <div>
              <h5>Summary</h5>
              <p className="ids-rule__desc">{summary}</p>
              {rule.description && rule.description !== summary ? (
                <p className="ids-rule__desc">{rule.description}</p>
              ) : null}
            </div>
            <div>
              <h5>Policy</h5>
              <dl className="ids-rule__dl">
                <dt>Action</dt>
                <dd>{action}</dd>
                <dt>Severity</dt>
                <dd>{rule.severity || '—'}</dd>
                {rule.procedure ? (
                  <>
                    <dt>Procedure</dt>
                    <dd>{rule.procedure}</dd>
                  </>
                ) : null}
                {rule.attack_pattern ? (
                  <>
                    <dt>Pattern</dt>
                    <dd>{rule.attack_pattern}</dd>
                  </>
                ) : null}
                {rule.reference ? (
                  <>
                    <dt>Reference</dt>
                    <dd>{rule.reference}</dd>
                  </>
                ) : null}
              </dl>
            </div>
            {(rule.ir21_checks?.length || rule.validation_logic) && (
              <div>
                <h5>IR.21 / Validation</h5>
                {rule.ir21_checks && rule.ir21_checks.length > 0 && (
                  <div className="ids-rule__checks">{rule.ir21_checks.join(' · ')}</div>
                )}
                {rule.validation_logic ? <pre className="ids-rule__code">{rule.validation_logic}</pre> : null}
              </div>
            )}
          </div>
          {rule.rule_text && <pre className="ids-rule__code">{rule.rule_text}</pre>}
        </div>
      )}
    </div>
  )
}

/* ---------- Main ---------- */

const IDSDashboard: FC<{ initialTab?: DashboardTab }> = ({ initialTab = 'overview' }) => {
  const [metrics, setMetrics] = useState<IDSMetrics | null>(null)
  const [offline, setOffline] = useState(false)
  const [traffic, setTraffic] = useState<TrafficEvent[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [rules, setRules] = useState<Rule[]>([])
  const [partners, setPartners] = useState<Partner[]>([])
  const [selectedEvent, setSelectedEvent] = useState<TrafficEvent | null>(null)
  const [investigation, setInvestigation] = useState<InvestigationBrief | null>(null)
  const [investigateLoading, setInvestigateLoading] = useState(false)
  const [investigateError, setInvestigateError] = useState<string | null>(null)
  const [selectedPartner, setSelectedPartner] = useState<Partner | null>(null)
  const [activeTab, setActiveTab] = useState<DashboardTab>(initialTab)
  const [ruleFilter, setRuleFilter] = useState<'all' | 'CAT1' | 'CAT2' | 'CAT3'>('all')
  const [ruleQuery, setRuleQuery] = useState('')
  const [partnerQuery, setPartnerQuery] = useState('')
  const [trafficQuery, setTrafficQuery] = useState('')
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null)
  const [isLive] = useState(true)
  const [streamPaused, setStreamPaused] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const refreshIntervalRef = useRef<number | null>(null)

  useEffect(() => {
    setActiveTab(initialTab)
  }, [initialTab])

  const refreshData = useCallback(async () => {
    try {
      const [m, t, a, r, p] = await Promise.all([
        fetchIDSStatus(),
        fetchTraffic(100),
        fetchAlerts(50),
        fetchRules(),
        fetchPartners(),
      ])
      setMetrics(m)
      setTraffic(t)
      setAlerts(a)
      setRules(r)
      setPartners(p)
      setOffline(false)
    } catch (err) {
      console.error('[IDS] Refresh failed:', err)
      setOffline(true)
    }
  }, [])

  const connectWebSocket = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    try {
      const ws = new WebSocket(idsLiveWsUrl())
      ws.onopen = () => console.log('[IDS] WebSocket connected')
      ws.onmessage = (ev) => {
        if (streamPaused) return
        try {
          const event = JSON.parse(ev.data)
          if (event.event_type === 'packet' || event.event_type === 'decision') {
            setTraffic((prev) => [
              {
                event_id: event.event_id || event.data?.event_id,
                timestamp: event.timestamp || event.data?.timestamp,
                protocol: event.data?.protocol || '',
                source: event.data?.source || '',
                destination: event.data?.destination || '',
                global_title: event.data?.global_title,
                origin_realm: event.data?.origin_realm,
                procedure: event.data?.procedure || '',
                subscriber_id_masked: event.data?.subscriber_id_masked,
                category: event.category || event.data?.category || '',
                decision: event.data?.decision || '',
                rule_id: event.data?.rule_id,
                confidence: event.data?.confidence || 1,
                processing_latency_ms: event.data?.processing_latency_ms || 0,
              },
              ...prev.slice(0, 99),
            ])
          }
          if (event.event_type === 'alert') {
            setAlerts((prev) => [event.data, ...prev.slice(0, 49)])
          }
          if ((event.event_type === 'metric' || event.event_type === 'status') && event.data?.metrics) {
            setMetrics((prev) => ({ ...(prev as IDSMetrics), ...event.data.metrics }))
          }
        } catch {
          /* heartbeat */
        }
      }
      ws.onclose = () => {
        wsRef.current = null
        setTimeout(() => {
          if (isLive) connectWebSocket()
        }, 3000)
      }
      ws.onerror = (err) => console.error('[IDS] WebSocket error:', err)
      wsRef.current = ws
    } catch (err) {
      console.error('[IDS] WebSocket connection failed:', err)
    }
  }, [isLive, streamPaused])

  useEffect(() => {
    refreshData()
    refreshIntervalRef.current = window.setInterval(() => {
      if (isLive) refreshData()
    }, 5000)
    connectWebSocket()
    return () => {
      if (refreshIntervalRef.current) clearInterval(refreshIntervalRef.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [refreshData, connectWebSocket, isLive])

  const handleStartStop = async () => {
    if (metrics?.running) await stopIDS()
    else await startIDS()
    await refreshData()
  }

  const handleEnforcementToggle = async () => {
    if (!metrics) return
    await setEnforcementMode(metrics.enforcement_mode !== 'enforce')
    await refreshData()
  }

  const handleAcknowledge = async (alertId: string) => {
    await acknowledgeAlert(alertId)
    setAlerts((prev) => prev.map((a) => (a.alert_id === alertId ? { ...a, acknowledged: true } : a)))
  }

  const openInvestigate = useCallback(
    async (target: { event?: TrafficEvent | null; alertId?: string; ruleId?: string }) => {
      const event = target.event || null
      setSelectedEvent(event)
      setInvestigation(null)
      setInvestigateError(null)
      setInvestigateLoading(true)
      try {
        const brief = await investigateEvent({
          eventId: event?.event_id,
          alertId: target.alertId,
          ruleId: target.ruleId || event?.rule_id,
        })
        setInvestigation(brief)
        if (!event && brief) {
          const linked =
            traffic.find((t) => t.event_id === brief.event_id || t.rule_id === brief.detection_rule) || null
          if (linked) setSelectedEvent(linked)
        }
      } catch (err) {
        console.error('[IDS] Investigate failed:', err)
        setInvestigateError(err instanceof Error ? err.message : String(err))
      } finally {
        setInvestigateLoading(false)
      }
    },
    [traffic],
  )

  const closeInvestigate = () => {
    setSelectedEvent(null)
    setInvestigation(null)
    setInvestigateError(null)
    setInvestigateLoading(false)
  }

  const filteredRules = rules.filter((rule) => {
    if (ruleFilter === 'CAT1' && rule.category !== 'CAT1') return false
    if (ruleFilter === 'CAT2' && rule.category !== 'CAT2') return false
    if (ruleFilter === 'CAT3' && !rule.category?.startsWith('CAT3')) return false
    const q = ruleQuery.trim().toLowerCase()
    if (!q) return true
    return [rule.rule_id, rule.name, rule.description, rule.summary, rule.protocol, rule.attack_pattern]
      .join(' ')
      .toLowerCase()
      .includes(q)
  })

  const filteredTraffic = traffic.filter((e) => {
    const q = trafficQuery.trim().toLowerCase()
    if (!q) return true
    return [e.protocol, e.source, e.destination, e.procedure, e.category, e.decision, e.global_title, e.origin_realm]
      .join(' ')
      .toLowerCase()
      .includes(q)
  })

  const openAlerts = alerts.filter((a) => !a.acknowledged).length
  const focusMode = !['overview', 'analytics'].includes(activeTab)
  const sectionTitle: Record<DashboardTab, string> = {
    overview: 'Overview',
    partners: 'IR.21 Partners',
    traffic: 'Live Traffic',
    alerts: 'Alerts',
    rules: 'Rules & Policies',
    threats: 'Dashboard',
    analytics: 'Analytics',
    summary: 'Summary',
  }
  const sectionHint: Record<DashboardTab, string> = {
    overview: `${metrics?.packets_inspected || 0} inspected · ${metrics?.packets_blocked || 0} blocked · ${openAlerts} open alerts`,
    partners: `${partners.length} enrolled IR.21 operators`,
    traffic: `${filteredTraffic.length} events in view · stream ${streamPaused ? 'paused' : 'live'}`,
    alerts: `${alerts.length} total · ${openAlerts} unacknowledged`,
    rules: `${filteredRules.length} rules shown · CAT1 block · CAT2 validate · CAT3 escalate`,
    threats: `${metrics?.cat1_matches || 0} CAT1 · ${metrics?.cat2_blocks || 0} CAT2 · ${metrics?.cat3_escalations || 0} CAT3`,
    analytics: `avg latency ${(metrics?.avg_latency_ms || 0).toFixed(1)} ms · uptime ${formatDuration(metrics?.uptime_seconds || 0)}`,
    summary: `${partners.length} partners · ${rules.length} rules · ${openAlerts} alerts`,
  }

  return (
    <div className={classNames('ids-dashboard', 'ids-dashboard--live', focusMode && 'ids-dashboard--focus', activeTab === 'overview' && 'ids-dashboard--overview', activeTab === 'threats' && 'ids-dashboard--threats')}>
      <header className="ids-pagehead ids-pagehead--live">
        <div className="ids-pagehead__tower" aria-hidden>
          <svg viewBox="0 0 360 200" fill="none">
            <path d="M250 188 L290 48 L330 188" stroke="currentColor" strokeWidth="1.4" />
            <path d="M270 188 L290 78 L310 188" stroke="currentColor" strokeWidth="1.2" opacity="0.7" />
            <circle cx="290" cy="42" r="5" fill="currentColor" />
            <path d="M268 34 a28 28 0 0 1 44 0" stroke="currentColor" strokeWidth="1.2" opacity="0.8" />
            <path d="M250 22 a48 48 0 0 1 80 0" stroke="currentColor" strokeWidth="1" strokeDasharray="4 3" opacity="0.5" />
            <path d="M40 160 C90 120 140 150 190 90 C230 50 270 80 340 40" stroke="currentColor" strokeWidth="1" opacity="0.35" />
            <circle cx="90" cy="132" r="2.2" fill="currentColor" opacity="0.7" />
            <circle cx="160" cy="118" r="2.2" fill="currentColor" opacity="0.55" />
            <circle cx="220" cy="78" r="2.2" fill="currentColor" opacity="0.45" />
          </svg>
        </div>
        <div className="ids-pagehead__copy">
          <p className="ids-pagehead__kicker">SOC · {sectionTitle[activeTab]}</p>
          <div className="ids-pagehead__title-row">
            <h1>{sectionTitle[activeTab]}</h1>
            <span className="ids-live ids-live--pulse">
              <span className="ids-live__dot" />
              LIVE
            </span>
            <StatusBadge status={metrics?.running ? 'ONLINE' : 'OFFLINE'} pulse={metrics?.running} />
            <StatusBadge status={metrics?.dry_run ? 'DRY_RUN' : 'ENFORCE'} />
          </div>
          <p className="ids-pagehead__sub">{sectionHint[activeTab]}</p>
        </div>
        <div className="ids-commands">
          <button
            type="button"
            className={classNames('ids-btn', metrics?.running && 'ids-btn--danger')}
            onClick={handleStartStop}
          >
            {metrics?.running ? 'STOP IDS' : 'START IDS'}
          </button>
          <button type="button" className="ids-btn ids-btn--secure ids-btn--outline-cyan" onClick={handleEnforcementToggle}>
            <IconShield />
            {metrics?.dry_run ? 'ENFORCE' : 'DRY RUN'}
          </button>
          <button type="button" className="ids-btn ids-btn--ghost" onClick={refreshData} title="Refresh">
            <IconRefresh />
          </button>
        </div>
      </header>

      {offline && (
        <div className="ids-offline">
          <strong>SIGNALING ENGINE OFFLINE</strong>
          Unable to reach /api/ids. Retrying on live refresh.
          <div style={{ marginTop: 10 }}>
            <button type="button" className="ids-btn" onClick={refreshData}>
              Retry Connection
            </button>
          </div>
        </div>
      )}

      <main className="ids-content">
        {activeTab === 'overview' && (
          <div className="ov-board">
            <div className="ov-kpi-row ov-kpi-row--six">
              <ThreatKpiCard label="Inspected" value={metrics?.packets_inspected || 0} tone="cyan" hint="packets" />
              <ThreatKpiCard label="Allowed" value={metrics?.packets_allowed || 0} tone="success" hint="pass" />
              <ThreatKpiCard label="Blocked" value={metrics?.packets_blocked || 0} tone="danger" hint="deny" />
              <ThreatKpiCard label="Escalated" value={metrics?.packets_escalated || 0} tone="amber" hint="CAT3" />
              <ThreatKpiCard label="Open Alerts" value={openAlerts} tone="blue" hint="triage" />
              <ThreatKpiCard label="Latency" value={`${(metrics?.avg_latency_ms || 0).toFixed(1)} ms`} tone="cyan" hint="avg" />
            </div>
            <div className="ov-mid ov-mid--work">
              <ThreatFeed
                alerts={alerts}
                traffic={traffic}
                onViewAll={() => setActiveTab('alerts')}
                onSelectEvent={(event) => {
                  void openInvestigate({ event, ruleId: event.rule_id })
                }}
              />
              <div className="ov-side">
                <ThreatActors alerts={alerts} traffic={traffic} />
                <TrafficComposition metrics={metrics} />
              </div>
            </div>
            <div className="ov-bottom">
              <SecondaryAnalytics metrics={metrics} />
              <div className="ids-panel ov-partners">
                <div className="ids-panel__head">
                  <h3 className="ids-panel__title">IR.21 Partners</h3>
                  <button type="button" className="ids-panel__link" onClick={() => setActiveTab('partners')}>
                    Full table →
                  </button>
                </div>
                <div className="ids-panel__body ov-partners__body">
                  <PartnerTable partners={partners.slice(0, 6)} query="" onSelect={setSelectedPartner} />
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="ov-board ov-board--analytics">
            <div className="ov-kpi-row">
              <ThreatKpiCard label="CAT1 Hits" value={metrics?.cat1_matches || 0} tone="cyan" />
              <ThreatKpiCard label="CAT2 Blocks" value={metrics?.cat2_blocks || 0} tone="violet" />
              <ThreatKpiCard label="CAT3 Events" value={metrics?.cat3_escalations || 0} tone="amber" />
              <ThreatKpiCard label="Avg Latency" value={`${metrics?.avg_latency_ms?.toFixed(1) || 0} ms`} tone="blue" />
            </div>
            <div className="ov-analytics-grid">
              <SecondaryAnalytics metrics={metrics} />
              <ExploitationTrends metrics={metrics} />
            </div>
          </div>
        )}

        {activeTab === 'partners' && (
          <>
            <div className="ids-tabs__tools">
              <input
                className="ids-search"
                placeholder="Search operator, TADIG, realm, MCC/MNC…"
                value={partnerQuery}
                onChange={(e) => setPartnerQuery(e.target.value)}
              />
              <span className="ids-tools__meta">{partners.length} partners</span>
            </div>
            <PartnerTable partners={partners} query={partnerQuery} onSelect={setSelectedPartner} />
          </>
        )}

        {activeTab === 'traffic' && (
          <>
            <div className="ids-tabs__tools">
              <input
                className="ids-search"
                placeholder="Search IMSI, GT, protocol, decision…"
                value={trafficQuery}
                onChange={(e) => setTrafficQuery(e.target.value)}
              />
              <button type="button" className="ids-btn ids-btn--sm" onClick={() => setStreamPaused((p) => !p)}>
                {streamPaused ? 'Resume' : 'Pause'}
              </button>
              <button type="button" className="ids-btn ids-btn--sm ids-btn--ghost" onClick={() => setTraffic([])}>
                Clear
              </button>
              <span className="ids-tools__meta">{filteredTraffic.length} events</span>
            </div>
            <div className="ids-traffic">
              <table className="ids-traffic__table">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Protocol</th>
                    <th>Signal</th>
                    <th>Peer</th>
                    <th>Subscriber</th>
                    <th>Rule</th>
                    <th>Decision</th>
                    <th>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTraffic.map((event) => (
                    <tr
                      key={event.event_id}
                      className={classNames(
                        'ids-traffic__row',
                        event.decision === 'BLOCK' && 'ids-traffic__row--block',
                        event.decision === 'ESCALATE' && 'ids-traffic__row--esc',
                      )}
                      onClick={() => {
                        void openInvestigate({ event, ruleId: event.rule_id })
                      }}
                    >
                      <td className="ids-traffic__cell ids-traffic__cell--time" title={formatTime(event.timestamp)}>
                        {formatUtcClock(event.timestamp)}
                      </td>
                      <td className="ids-traffic__cell">{event.protocol || '—'}</td>
                      <td className="ids-traffic__cell">
                        <div className="ids-traffic__signal">
                          <strong>{humanizeSignal(event.procedure || event.protocol)}</strong>
                          <span>{event.category || '—'}</span>
                        </div>
                      </td>
                      <td className="ids-traffic__cell ids-traffic__cell--mono">{eventPeer(event)}</td>
                      <td className="ids-traffic__cell ids-traffic__cell--mono">{event.subscriber_id_masked || '—'}</td>
                      <td className="ids-traffic__cell ids-traffic__cell--mono">{event.rule_id || '—'}</td>
                      <td className="ids-traffic__cell">
                        <StatusBadge status={event.decision} />
                      </td>
                      <td className="ids-traffic__cell ids-traffic__cell--latency">
                        {(event.processing_latency_ms || 0).toFixed(1)}ms
                      </td>
                    </tr>
                  ))}
                  {filteredTraffic.length === 0 && (
                    <tr>
                      <td colSpan={8}>
                        <EmptyState
                          title="No live traffic"
                          hint="Inspected packets stream here once IDS is running and signaling arrives."
                        />
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activeTab === 'alerts' && (
          <div className="ids-alerts ids-alerts--table">
            <div className="ids-alerts__head" aria-hidden>
              <span>When</span>
              <span>Decision</span>
              <span>Signal</span>
              <span>Peer / IMSI</span>
              <span>Rule</span>
              <span>Severity</span>
              <span />
            </div>
            {alerts.map((alert) => {
              const linked = traffic.find((t) => t.event_id === alert.packet_event_id)
              return (
                <div
                  key={alert.alert_id}
                  className={classNames(
                    'ids-alert-row',
                    `ids-alert-row--${(alert.severity || 'info').toLowerCase()}`,
                    alert.acknowledged && 'ids-alert-row--acked',
                  )}
                >
                  <span className="ids-alert-row__when" title={formatTime(alert.timestamp)}>
                    {formatRelative(alert.timestamp)}
                  </span>
                  <span className="ids-alert-row__dec">
                    <StatusBadge status={alert.decision} />
                    <StatusBadge status={alert.category} />
                  </span>
                  <span className="ids-alert-row__signal">
                    <strong>{alertHeadline(alert)}</strong>
                    <span>{linked?.protocol || alert.attack_pattern || '—'}</span>
                  </span>
                  <span className="ids-alert-row__peer">
                    <code>{linked ? eventPeer(linked) : '—'}</code>
                    <code>{alert.subscriber_id_masked || '—'}</code>
                  </span>
                  <span className="ids-alert-row__rule">{alert.detection_rule || '—'}</span>
                  <span className={classNames('ti-sev', `ti-sev--${(alert.severity || 'info').toLowerCase()}`)}>
                    {(alert.severity || 'info').toUpperCase()}
                  </span>
                  <span className="ids-alert-row__actions">
                    <button
                      type="button"
                      className="ti-act"
                      onClick={() => {
                        void openInvestigate({
                          event: linked || null,
                          alertId: alert.alert_id,
                          ruleId: alert.detection_rule,
                        })
                      }}
                    >
                      Investigate
                    </button>
                    {!alert.acknowledged && (
                      <button type="button" className="ti-act ti-act--ghost" onClick={() => handleAcknowledge(alert.alert_id)}>
                        Ack
                      </button>
                    )}
                  </span>
                </div>
              )
            })}
            {alerts.length === 0 && (
              <EmptyState
                title="No unacknowledged alerts"
                hint="All alerts have been reviewed or there are currently no active alerts."
                action={
                  <button type="button" className="ids-btn ids-btn--ghost" onClick={() => refreshData()} style={{ marginTop: 12 }}>
                    <IconRefresh /> Refresh
                  </button>
                }
              />
            )}
          </div>
        )}

        {activeTab === 'rules' && (
          <>
            <div className="ids-tabs__tools">
              <input
                className="ids-search"
                placeholder="Search rules, SIDs, protocols…"
                value={ruleQuery}
                onChange={(e) => setRuleQuery(e.target.value)}
              />
              {(['all', 'CAT1', 'CAT2', 'CAT3'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  className={classNames('ids-btn ids-btn--sm', ruleFilter === f && 'ids-btn--secure')}
                  onClick={() => setRuleFilter(f)}
                >
                  {f}
                </button>
              ))}
              <span className="ids-tools__meta">{filteredRules.length} rules</span>
            </div>
            <div className="ids-rules">
              <div className="ids-rules__head" aria-hidden>
                <span>Rule ID</span>
                <span>CAT</span>
                <span>Signal / Summary</span>
                <span>Protocol</span>
                <span>Gen</span>
                <span>Action</span>
                <span>Severity</span>
                <span>SID</span>
                <span />
              </div>
              {filteredRules.map((rule) => (
                <RuleRow
                  key={rule.rule_id}
                  rule={rule}
                  expanded={expandedRuleId === rule.rule_id}
                  onToggle={() => setExpandedRuleId(expandedRuleId === rule.rule_id ? null : rule.rule_id)}
                />
              ))}
              {filteredRules.length === 0 && (
                <EmptyState title="No rules match this filter" hint="Try another CAT filter or clear the search." />
              )}
            </div>
          </>
        )}

        {activeTab === 'threats' && (
          <ThreatIntelBoard
            metrics={metrics}
            alerts={alerts}
            traffic={traffic}
            onAck={handleAcknowledge}
            onInvestigate={(target) => {
              void openInvestigate(target)
            }}
            onViewAlerts={() => setActiveTab('alerts')}
          />
        )}

        {activeTab === 'summary' && (
          <div className="ov-board">
            <div className="ov-kpi-row">
              <ThreatKpiCard label="Partners" value={partners.length} />
              <ThreatKpiCard label="Rules" value={rules.length} />
              <ThreatKpiCard label="Open Alerts" value={openAlerts} />
              <ThreatKpiCard label="Uptime" value={formatDuration(metrics?.uptime_seconds || 0)} />
            </div>
          </div>
        )}
      </main>

      <InvestigateDrawer
        event={selectedEvent}
        brief={investigation}
        loading={investigateLoading}
        error={investigateError}
        onClose={closeInvestigate}
      />
      <PartnerDrawer partner={selectedPartner} onClose={() => setSelectedPartner(null)} />
    </div>
  )
}

export default IDSDashboard
