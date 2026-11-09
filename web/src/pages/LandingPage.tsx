import { AppLogo } from '../components/AppLogo'
import '../landing.css'

export function LandingPage() {
  return (
    <main className="landing-page">
      <header className="landing-header">
        <a className="landing-logo-link" href="/" aria-label="Private Ledger home">
          <AppLogo className="landing-logo" />
        </a>
        <nav className="landing-navigation" aria-label="Public navigation">
          <a className="landing-open-app" href="/app">Open app</a>
        </nav>
      </header>

      <section className="landing-hero" aria-labelledby="landing-title">
        <p className="landing-environment">Testnet</p>
        <h1 className="landing-title" id="landing-title">Confidential credit on NEAR.</h1>
        <p className="landing-description">
          Lend through shared vaults. Borrow with encrypted loan amounts.
        </p>
      </section>
    </main>
  )
}
