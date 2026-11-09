export function AppLogo({ className = '' }: { className?: string }) {
  return <svg className={`app-logo ${className}`} viewBox="0 0 36 36" fill="none" aria-hidden="true" focusable="false">
    <ellipse cx="18" cy="18" rx="11" ry="16" transform="rotate(-35 18 18)" stroke="currentColor" strokeWidth="1.3" />
    <ellipse cx="18" cy="18" rx="11" ry="16" transform="rotate(35 18 18)" stroke="currentColor" strokeWidth="1.3" />
    <circle cx="18" cy="18" r="3" fill="currentColor" />
  </svg>
}
