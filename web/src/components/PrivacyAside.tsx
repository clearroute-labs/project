import { StatusBadge } from './ui'

export function PrivacyAside() {
 return <aside className="overview-aside" aria-label="The clear perspective">
  <div className="dune-context"><p className="eyebrow">The clear perspective</p><h2>Public capital.<br />Private credit.</h2></div>
  <section className="perspective-section"><h3>Know what is visible</h3><div className="privacy-row"><span>Vault accounting</span><StatusBadge>Public</StatusBadge></div><div className="privacy-row"><span>Loan amounts</span><StatusBadge>Encrypted</StatusBadge></div><div className="privacy-row"><span>Identities & timing</span><StatusBadge>Public</StatusBadge></div><details className="privacy-details"><summary>Understand privacy <span aria-hidden="true">↗</span></summary><p>Amounts entering or leaving the confidential system are public. Registered reader keys define access to encrypted values. Decrypted data stays in this browser unless you explicitly export it.</p></details></section>
  <section className="perspective-section"><h3>Know the risk</h3><p>Credit is underwritten offchain. Vault shares can lose value. Returns and principal are not guaranteed.</p></section>
 </aside>
}
