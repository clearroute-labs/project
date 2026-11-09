import { AppLogo } from '../components/AppLogo'
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

function CreditDiagram() {
  return <figure className="credit-diagram" aria-label="Public vault capital funds loans with encrypted amounts, readable only through authorized views.">
    <figcaption className="diagram-caption"><span className="diagram-cross" aria-hidden="true">+</span> Protocol illustration <span>01 — 03</span></figcaption>
    <div className="diagram-grid" aria-hidden="true" />
    <div className="ledger-card ledger-public">
      <div className="ledger-heading"><span className="ledger-index">01</span><NavIcon name="vault" /><span className="ledger-tag">Public</span></div>
      <h2>Shared capital.</h2>
      <p>Vault liquidity & accounting</p>
      <div className="ledger-lines" aria-hidden="true"><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /></div>
    </div>
    <div className="ledger-connector" aria-hidden="true"><span />↓</div>
    <div className="ledger-card ledger-private">
      <div className="ledger-heading"><span className="ledger-index">02</span><NavIcon name="security" /><span className="ledger-tag">Encrypted</span></div>
      <h2>Private credit.</h2>
      <div className="ledger-secret"><span>Loan amount</span><span aria-label="Encrypted amount">•••• ••••</span></div>
      <div className="ledger-secret"><span>Repayment</span><span aria-label="Encrypted amount">•••• ••••</span></div>
      <p className="ledger-private-note">Broker-underwritten. Proof-verified.</p>
    </div>
    <div className="ledger-reader"><NavIcon name="audit" /><div><strong>Authorized view</strong><span>Access follows the keys.</span></div><span className="reader-dot" aria-hidden="true" /></div>
    <div className="diagram-footnote"><span>Public record</span><span className="diagram-footnote-line" /><span>Selective visibility</span></div>
  </figure>
}

function WorkspacePreview() {
  return <div className="workspace-preview" aria-label="Illustrative lender workspace, not live account data">
    <div className="preview-topbar"><div><AppLogo /><strong>Lender overview</strong></div><span className="preview-sample">Illustrative testnet data</span></div>
    <div className="preview-content">
      <div className="preview-title"><h3>A clear view of your capital.</h3><span className="preview-network"><span aria-hidden="true" />NEAR Testnet</span></div>
      <dl className="preview-metrics">
        <div><dt>Net asset value</dt><dd>124,875<span>TEST · after provisions</span></dd></div>
        <div><dt>Available liquidity</dt><dd>116,500<span>TEST</span></dd></div>
        <div><dt>Vault positions</dt><dd>2<span>Public share positions</span></dd></div>
        <div><dt>Payout operations</dt><dd>0<span>No pending payouts</span></dd></div>
      </dl>
      <div className="preview-table-wrap" role="region" aria-label="Illustrative public vault records" tabIndex={0}>
        <table className="preview-table"><caption>Public vault positions · sample data</caption><thead><tr><th scope="col">Vault</th><th scope="col">Net assets</th><th scope="col">Available</th><th scope="col">Accounting</th></tr></thead><tbody>
          <tr><th scope="row"><span className="preview-vault-mark" aria-hidden="true">01</span>Working capital</th><td>94,875 TEST</td><td>86,500 TEST</td><td><span className="preview-status">Current</span></td></tr>
          <tr><th scope="row"><span className="preview-vault-mark" aria-hidden="true">02</span>Business credit</th><td>30,000 TEST</td><td>30,000 TEST</td><td><span className="preview-status">Current</span></td></tr>
        </tbody></table>
      </div>
      <p className="preview-note">Public vault accounting. Individual loan amounts stay encrypted.</p>
    </div>
  </div>
}

export function LandingPage() {
  return <div className="landing-page">
    <a className="skip-link" href="#landing-main">Skip to content</a>
    <header className="landing-header">
      <div className="landing-header-inner">
        <a className="landing-brand" href="/" aria-label="ClearRoute home"><AppLogo /><span>ClearRoute</span></a>
        <nav className="landing-navigation" aria-label="Public navigation"><a href="#protocol">Protocol</a><a href="#workspaces">Workspaces</a></nav>
        <div className="landing-header-actions"><span className="landing-network"><span aria-hidden="true" />NEAR Testnet</span><a className="landing-button landing-button-small" href="/app">Open app <Arrow diagonal /></a></div>
      </div>
    </header>

    <main id="landing-main" tabIndex={-1}>
      <section className="landing-hero landing-container" aria-labelledby="landing-title">
        <div className="landing-hero-copy">
          <p className="landing-eyebrow"><span className="landing-status-dot" />Confidential lending on NEAR</p>
          <h1 id="landing-title">Credit, with<br />a <span>private side.</span></h1>
          <p className="landing-description">Public vaults. Encrypted loan amounts.<br className="desktop-break" /> A clearer way to coordinate credit.</p>
          <div className="landing-hero-actions"><a className="landing-button" href="/app">Open app <Arrow /></a><a className="landing-text-link" href="#protocol">How it works <span aria-hidden="true">↓</span></a></div>
          <p className="landing-hero-note">Built for shared capital. Designed for selective visibility.</p>
        </div>
        <CreditDiagram />
      </section>

      <section id="protocol" className="landing-protocol" aria-labelledby="protocol-heading">
        <div className="landing-container">
          <div className="landing-section-label"><span>01 / The protocol</span><h2 id="protocol-heading">Capital moves. Details stay private.</h2></div>
          <div className="landing-steps">{steps.map((step) => <article key={step.number}><span className="step-number">{step.number}</span><h3>{step.title}</h3><p>{step.text}</p></article>)}</div>
          <p className="protocol-disclosure">Account identities, timing and public boundary amounts remain visible on-chain.</p>
        </div>
      </section>

      <section id="workspaces" className="landing-workspaces landing-container" aria-labelledby="workspaces-heading">
        <div className="landing-section-heading"><div><p className="landing-eyebrow">02 / Your perspective</p><h2 id="workspaces-heading">One protocol.<br /><span>A view for every role.</span></h2></div><p>From the first deposit to the final settlement, each workspace brings the right information into focus.</p></div>
        <WorkspacePreview />
        <div className="workspace-roles">{workspaces.map((workspace) => <a key={workspace.role} className="workspace-role" href={`/app#${workspace.path}`}><div className="workspace-role-label"><NavIcon name={workspace.icon} /><span>{workspace.role}</span><Arrow diagonal /></div><h3>{workspace.title}</h3><p>{workspace.description}</p></a>)}</div>
      </section>

      <section className="landing-privacy" aria-labelledby="privacy-heading"><div className="landing-container landing-privacy-inner">
        <div><p className="landing-eyebrow">03 / A deliberate boundary</p><h2 id="privacy-heading">Privacy where it matters.<br /><span>Clarity where it counts.</span></h2></div>
        <div className="privacy-facts"><div><span className="privacy-marker" aria-hidden="true">+</span><div><h3>Encrypted amounts</h3><p>Loan amounts, repayments and confidential balances are readable through authorized keys.</p></div></div><div><span className="privacy-marker" aria-hidden="true">↗</span><div><h3>A public record</h3><p>Accounts, timing and vault accounting remain visible. Confidential amounts do not mean anonymous activity.</p></div></div></div>
      </div></section>

      <section className="landing-questions landing-container" aria-labelledby="questions-heading"><div><p className="landing-eyebrow">Before you begin</p><h2 id="questions-heading">A few things<br />worth knowing.</h2><a className="landing-text-link" href="/app">Explore the workspace <Arrow /></a></div><div className="landing-faq">
        <details><summary>Is ClearRoute running on mainnet?</summary><p>This prototype runs on NEAR testnet. Test assets have no monetary value. The workspace is for exploring the protocol and its workflows.</p></details>
        <details><summary>What can other people see?</summary><p>Account IDs, loan existence, timing and public vault accounting remain visible. Loan amounts and confidential balances are encrypted for their authorized readers. Public boundary amounts and small loan cohorts can still reveal information.</p></details>
        <details><summary>Are deposits or returns guaranteed?</summary><p>No. Brokers underwrite borrowers off-chain. Loans have no on-chain collateral or first-loss cover. Vault shares carry credit and liquidity risk, and redemptions depend on available liquidity and current accounting.</p></details>
        <details><summary>How do I keep access to private data?</summary><p>Confidential keys stay in your browser. A compatible passkey can unlock the encrypted copy saved on that device. Keep your encrypted recovery file: a synced passkey alone does not restore the browser’s stored data.</p></details>
      </div></section>
    </main>

    <footer className="landing-footer"><div className="landing-container"><a className="landing-brand" href="/" aria-label="ClearRoute home"><AppLogo /><span>ClearRoute</span></a><p>Public capital. Private credit.</p><span className="landing-network"><span aria-hidden="true" />NEAR Testnet</span></div><div className="landing-container landing-footer-bottom"><span>Confidential lending on NEAR.</span><p>Testnet prototype. Lending carries credit and liquidity risk. Principal is not guaranteed.</p></div></footer>
  </div>
}
