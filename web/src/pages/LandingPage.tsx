import { AppLogo } from '../components/AppLogo'
import { DesertHero } from '../components/DesertHero'
import { NavIcon } from '../components/NavIcon'
import '../landing.css'

const steps = [
  { number: '01', title: 'Fund a vault.', text: 'Supply capital to a public, single-asset vault. Hold shares and follow its liquidity and accounting.' },
  { number: '02', title: 'Agree a loan.', text: 'A broker underwrites off-chain. Both parties approve the agreement, with loan amounts encrypted.' },
  { number: '03', title: 'Repay. Then settle.', text: 'Borrowers repay privately. Public settlement returns vault principal before recognizing realized yield.' },
]

const workspaces = [
  { role: 'Lender', icon: 'vault' as const, path: '/lender/vaults', title: 'Put capital to work.', description: 'Explore vaults, manage your shares and follow public accounting.' },
  { role: 'Broker', icon: 'loan' as const, path: '/broker/loans', title: 'Coordinate credit.', description: 'Originate agreements, service loans and settle back to your vault.' },
  { role: 'Borrower', icon: 'wallet' as const, path: '/borrower/agreements', title: 'Keep amounts private.', description: 'Review your agreement, access your balance and manage repayments.' },
  { role: 'Auditor', icon: 'audit' as const, path: '/auditor/loans', title: 'See what is authorized.', description: 'Decrypt the views assigned to your keys, within their defined scope.' },
]

function Arrow({ diagonal = false }: { diagonal?: boolean }) {
  return <svg className="landing-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={diagonal ? 'M6 18 18 6M6 6h12v12' : 'M4 12h16m-6-6 6 6-6 6'} /></svg>
}

export function LandingPage() {
  return <div className="landing-page">
    <a className="skip-link" href="#landing-main">Skip to content</a>
    <main id="landing-main" tabIndex={-1}>
      <DesertHero>
        <header className="landing-header"><a className="landing-brand" href="/" aria-label="clear home"><AppLogo /></a><nav aria-label="Public navigation"><a href="#protocol">Protocol</a><a href="/app" className="landing-button landing-button-small">Open app <Arrow diagonal /></a></nav></header>
        <div className="landing-hero-copy"><p className="landing-eyebrow">Confidential lending on NEAR</p><h1 id="landing-title">Capital moves.<br />Details stay private.</h1><p className="landing-description">Public vaults. Encrypted loan amounts.<br />A clearer way to coordinate credit.</p><a className="landing-button" href="/app">Enter the workspace <Arrow diagonal /></a></div>
        <div className="hero-bottom"><span>NEAR Testnet</span><a href="#protocol">How it works <span aria-hidden="true">↓</span></a><span>Public capital. Private credit.</span></div>
      </DesertHero>
      <section id="protocol" className="landing-protocol" aria-labelledby="protocol-heading">
        <div className="landing-container">
          <div className="landing-section-label"><span>01 / The protocol</span><h2 id="protocol-heading">A shared pool.<br />A private agreement.</h2></div>
          <div className="landing-steps">{steps.map((step) => <article key={step.number}><span className="step-number">{step.number}</span><h3>{step.title}</h3><p>{step.text}</p></article>)}</div>
          <p className="protocol-disclosure">Account identities, timing and public boundary amounts remain visible on-chain.</p>
        </div>
      </section>

      <section id="workspaces" className="landing-workspaces landing-container" aria-labelledby="workspaces-heading">
        <div className="landing-section-heading"><div><p className="landing-eyebrow">02 / Your perspective</p><h2 id="workspaces-heading">One protocol.<br /><span>A view for every role.</span></h2></div><p>From the first deposit to the final settlement, each workspace brings the right information into focus.</p></div>

        <div className="workspace-roles">{workspaces.map((workspace) => <a key={workspace.role} className="workspace-role" href={`/app#${workspace.path}`}><div className="workspace-role-label"><NavIcon name={workspace.icon} /><span>{workspace.role}</span><Arrow diagonal /></div><h3>{workspace.title}</h3><p>{workspace.description}</p></a>)}</div>
      </section>

      <section className="landing-privacy" aria-labelledby="privacy-heading"><div className="landing-container landing-privacy-inner">
        <div><p className="landing-eyebrow">03 / A deliberate boundary</p><h2 id="privacy-heading">Privacy where it matters.<br /><span>Clarity where it counts.</span></h2></div>
        <div className="privacy-facts"><div><span className="privacy-marker" aria-hidden="true">+</span><div><h3>Encrypted amounts</h3><p>Loan amounts, repayments and confidential balances are readable through authorized keys.</p></div></div><div><span className="privacy-marker" aria-hidden="true">↗</span><div><h3>A public record</h3><p>Accounts, timing and vault accounting remain visible. Confidential amounts do not mean anonymous activity.</p></div></div></div>
      </div></section>

      <section className="landing-questions landing-container" aria-labelledby="questions-heading"><div><p className="landing-eyebrow">Before you begin</p><h2 id="questions-heading">A few things<br />worth knowing.</h2><a className="landing-text-link" href="/app">Explore the workspace <Arrow /></a></div><div className="landing-faq">
        <details><summary>Is clear running on mainnet?</summary><p>This prototype runs on NEAR testnet. Test assets have no monetary value. The workspace is for exploring the protocol and its workflows.</p></details>
        <details><summary>What can other people see?</summary><p>Account IDs, loan existence, timing and public vault accounting remain visible. Loan amounts and confidential balances are encrypted for their authorized readers. Public boundary amounts and small loan cohorts can still reveal information.</p></details>
        <details><summary>Are deposits or returns guaranteed?</summary><p>No. Brokers underwrite borrowers off-chain. Loans have no on-chain collateral or first-loss cover. Vault shares carry credit and liquidity risk, and redemptions depend on available liquidity and current accounting.</p></details>
        <details><summary>How do I keep access to private data?</summary><p>Confidential keys stay in your browser. A compatible passkey can unlock the encrypted copy saved on that device. Keep your encrypted recovery file: a synced passkey alone does not restore the browser’s stored data.</p></details>
      </div></section>
      <section className="landing-final landing-container" aria-labelledby="final-heading"><img src="/clear-dunes-mobile.webp" width="840" height="473" alt="" loading="lazy" /><div><p className="landing-eyebrow">Your next perspective</p><h2 id="final-heading">A clearer view<br />of private credit.</h2><a href="/app" className="landing-text-link">Open the workspace <Arrow diagonal /></a></div></section>
    </main>

    <footer className="landing-footer"><div className="landing-container"><a className="landing-brand" href="/" aria-label="clear home"><AppLogo /></a><p>Public capital. Private credit.</p><span className="landing-network"><span aria-hidden="true" />NEAR Testnet</span></div><div className="landing-container landing-footer-bottom"><span>Confidential lending on NEAR.</span><p>Testnet prototype. Lending carries credit and liquidity risk. Principal is not guaranteed.</p></div></footer>
  </div>
}
