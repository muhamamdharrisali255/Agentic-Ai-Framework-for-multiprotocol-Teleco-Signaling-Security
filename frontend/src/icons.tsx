import type { SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement>

const stroke = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.7,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
}

export function IconShield(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <path d="M12 3 4.8 6.2v5.4c0 4.6 3.1 8.7 7.2 9.7 4.1-1 7.2-5.1 7.2-9.7V6.2L12 3Z" />
      <path d="M8.8 12.2 11 14.5l4.3-5" />
    </svg>
  )
}

export function IconChat(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <path d="M5 6.5A2.5 2.5 0 0 1 7.5 4h9A2.5 2.5 0 0 1 19 6.5v7A2.5 2.5 0 0 1 16.5 16H10l-4.2 3.2c-.7.5-1.8 0-1.8-.8V6.5Z" />
    </svg>
  )
}

export function IconLibrary(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <path d="M5 5.5h5.5v13H5A1.5 1.5 0 0 1 3.5 17V7A1.5 1.5 0 0 1 5 5.5Z" />
      <path d="M10.5 5.5H19A1.5 1.5 0 0 1 20.5 7v10a1.5 1.5 0 0 1-1.5 1.5h-8.5" />
      <path d="M13.5 9h4M13.5 12.5h4" />
    </svg>
  )
}

export function IconSearch(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <circle cx="11" cy="11" r="6.2" />
      <path d="M16 16.5 20 20.5" />
    </svg>
  )
}

export function IconSettings(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <circle cx="12" cy="12" r="3.1" />
      <path d="M19.4 12.9a7.6 7.6 0 0 0 .06-1.8l2.04-1.58-2-3.46-2.4.72a7.7 7.7 0 0 0-1.56-.9L15.1 3H8.9l-.44 2.88a7.7 7.7 0 0 0-1.56.9l-2.4-.72-2 3.46L4.54 11.1a7.6 7.6 0 0 0 0 1.8L2.5 14.48l2 3.46 2.4-.72c.48.36 1 .66 1.56.9L8.9 21h6.2l.44-2.88c.56-.24 1.08-.54 1.56-.9l2.4.72 2-3.46-2.1-1.58Z" />
    </svg>
  )
}

export function IconSend(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <path d="M12 19V5" />
      <path d="M6 11l6-6 6 6" />
    </svg>
  )
}

export function IconStop(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" {...props}>
      <rect x="7" y="7" width="10" height="10" rx="1.5" />
    </svg>
  )
}

export function IconRefresh(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <path d="M20 12a8 8 0 1 1-2.2-5.5" />
      <path d="M20 5v5h-5" />
    </svg>
  )
}

export function IconMenu(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <path d="M5 7h14M5 12h14M5 17h14" />
    </svg>
  )
}

export function IconPlus(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" {...stroke} {...props}>
      <path d="M12 5v14M5 12h14" />
    </svg>
  )
}

export function IconUpload(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="28" height="28" {...stroke} {...props}>
      <path d="M12 16V6" />
      <path d="M8 10l4-4 4 4" />
      <path d="M5 18h14" />
    </svg>
  )
}

export function IconSpark(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <path d="M12 3.5 13.6 9H19l-4.4 3.3L16.2 18 12 14.8 7.8 18l1.6-5.7L5 9h5.4L12 3.5Z" />
    </svg>
  )
}

export function IconInspect(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <rect x="4" y="5" width="16" height="14" rx="2" />
      <path d="M4 9.5h16M8 5v4.5" />
    </svg>
  )
}

export function IconPulse(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <path d="M3 12h4l2.2-6 3.6 12L15.8 9 18 12h3" />
    </svg>
  )
}

export function IconAllow(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <path d="M6 12.5 10.2 17 18 8" />
    </svg>
  )
}

export function IconBlock(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <circle cx="12" cy="12" r="8" />
      <path d="M7.2 7.2 16.8 16.8" />
    </svg>
  )
}

export function IconWarn(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <path d="M12 4.5 21 20H3L12 4.5Z" />
      <path d="M12 10v4.5M12 17.2v.6" />
    </svg>
  )
}

export function IconClose(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" {...stroke} {...props}>
      <path d="M6 6 18 18M18 6 6 18" />
    </svg>
  )
}

export function IconBell(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <path d="M6.5 16.5h11" />
      <path d="M8 16.5V11a4 4 0 1 1 8 0v5.5" />
      <path d="M10.2 16.5a1.8 1.8 0 0 0 3.6 0" />
      <path d="M12 4.5V6" />
    </svg>
  )
}

export function IconHome(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <path d="M4.5 10.5 12 4.5l7.5 6V19a1.5 1.5 0 0 1-1.5 1.5h-3.5v-5h-5v5H6A1.5 1.5 0 0 1 4.5 19v-8.5Z" />
    </svg>
  )
}

export function IconLogout(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" {...stroke} {...props}>
      <path d="M10 12h10" />
      <path d="M16 8l4 4-4 4" />
      <path d="M13 4.5H7.5A2.5 2.5 0 0 0 5 7v10a2.5 2.5 0 0 0 2.5 2.5H13" />
    </svg>
  )
}
