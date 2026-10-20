/** Animated cybersecurity command-center backdrop: grid + neon signaling paths. */
export default function CommandCenterBg() {
  return (
    <div className="cc-bg" aria-hidden="true">
      <div className="cc-bg__photo" />
      <div className="cc-bg__vignette" />
      <div className="cc-bg__grid" />
      <svg className="cc-bg__net" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice">
        <defs>
          <linearGradient id="cc-flow-a" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0" />
            <stop offset="35%" stopColor="#22d3ee" stopOpacity="0.95" />
            <stop offset="70%" stopColor="#a855f7" stopOpacity="0.85" />
            <stop offset="100%" stopColor="#f43f5e" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="cc-flow-b" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0" />
            <stop offset="40%" stopColor="#22d3ee" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#6366f1" stopOpacity="0.15" />
          </linearGradient>
          <filter id="cc-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <radialGradient id="cc-node" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#8aebff" stopOpacity="1" />
            <stop offset="55%" stopColor="#22d3ee" stopOpacity="0.7" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Floor perspective grid hints */}
        <g opacity="0.18" stroke="#22d3ee" strokeWidth="0.6" fill="none">
          <path d="M80 760 L800 520 L1520 760" />
          <path d="M180 780 L800 560 L1420 780" />
          <path d="M280 800 L800 600 L1320 800" />
        </g>

        {/* Primary signaling arcs */}
        <g filter="url(#cc-glow)" fill="none" strokeLinecap="round">
          <path
            className="cc-bg__path cc-bg__path--a"
            d="M120 640 C 320 480, 420 420, 640 380 S 980 300, 1180 340 S 1420 480, 1500 220"
            stroke="url(#cc-flow-a)"
            strokeWidth="2.4"
          />
          <path
            className="cc-bg__path cc-bg__path--b"
            d="M80 280 C 280 360, 420 520, 620 560 S 980 620, 1220 540 S 1420 400, 1520 560"
            stroke="url(#cc-flow-b)"
            strokeWidth="2"
          />
          <path
            className="cc-bg__path cc-bg__path--c"
            d="M200 160 C 380 240, 520 200, 700 260 S 1000 420, 1180 480 S 1380 620, 1480 700"
            stroke="#22d3ee"
            strokeOpacity="0.45"
            strokeWidth="1.6"
          />
          <path
            className="cc-bg__path cc-bg__path--d"
            d="M260 780 C 480 700, 620 640, 820 600 S 1120 520, 1300 440"
            stroke="#a855f7"
            strokeOpacity="0.55"
            strokeWidth="1.8"
          />
        </g>

        {/* Hub nodes */}
        <g filter="url(#cc-glow)">
          <circle className="cc-bg__hub" cx="640" cy="380" r="18" fill="url(#cc-node)" />
          <circle className="cc-bg__hub cc-bg__hub--delay" cx="1180" cy="340" r="14" fill="url(#cc-node)" />
          <circle className="cc-bg__hub" cx="820" cy="600" r="12" fill="url(#cc-node)" />
          <circle className="cc-bg__hub cc-bg__hub--delay" cx="420" cy="520" r="10" fill="url(#cc-node)" />
        </g>

        {/* Mini telecom badges */}
        <g className="cc-bg__tags" fontFamily="ui-sans-serif, system-ui, sans-serif" fontSize="11" fontWeight="700">
          <g transform="translate(500 300)">
            <rect rx="6" width="36" height="18" fill="rgba(10,23,48,0.75)" stroke="#22d3ee" strokeWidth="1" />
            <text x="18" y="13" textAnchor="middle" fill="#8aebff">3G</text>
          </g>
          <g transform="translate(900 470)">
            <rect rx="6" width="36" height="18" fill="rgba(10,23,48,0.75)" stroke="#22d3ee" strokeWidth="1" />
            <text x="18" y="13" textAnchor="middle" fill="#8aebff">4G</text>
          </g>
          <g transform="translate(1260 390)">
            <rect rx="6" width="36" height="18" fill="rgba(10,23,48,0.75)" stroke="#a855f7" strokeWidth="1" />
            <text x="18" y="13" textAnchor="middle" fill="#c084fc">5G</text>
          </g>
        </g>

        {/* Traveling pulses along paths */}
        <circle r="4" fill="#8aebff" className="cc-bg__pulse">
          <animateMotion dur="7s" repeatCount="indefinite" path="M120 640 C 320 480, 420 420, 640 380 S 980 300, 1180 340 S 1420 480, 1500 220" />
        </circle>
        <circle r="3.5" fill="#c084fc" className="cc-bg__pulse">
          <animateMotion dur="9s" repeatCount="indefinite" path="M80 280 C 280 360, 420 520, 620 560 S 980 620, 1220 540 S 1420 400, 1520 560" />
        </circle>
        <circle r="3" fill="#22d3ee" className="cc-bg__pulse">
          <animateMotion dur="8s" begin="1.5s" repeatCount="indefinite" path="M260 780 C 480 700, 620 640, 820 600 S 1120 520, 1300 440" />
        </circle>
      </svg>
      <div className="cc-bg__scan" />
    </div>
  )
}
