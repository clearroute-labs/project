# Local product walkthrough

Run the setup commands in [README.md](../README.md), then start `pnpm demo`
with the directory containing the generated development artifacts. For example:

```sh
DEMO_PORT=5175 pnpm demo .artifacts/integration-v4
```

Wait for `Sandbox ready` and open the printed local URL. The launcher creates
an isolated chain, a test token and funded accounts, and serves the pinned proving artifacts.
Its assets have no monetary value. Restarting the launcher creates a new chain;
use its newly generated credentials and auditor backup.

## Accounts and private sessions

Use a separate browser tab for each role. Import the corresponding file from
`.local/demo/credentials/` through **Import sandbox credentials**. The workspace
selector changes the displayed tools; it does not change the signing account.

| Account file | Role |
| --- | --- |
| `broker.json` | Owns the vault, underwrites loans, and settles the book |
| `lender.json` | Deposits test tokens and redeems vault shares |
| `borrower.json` | Reviews agreements, receives private funds, and repays |
| `auditor.json` | Opens explicitly authorized audit views |
| `recipient.json` | Optional destination for private transfers or public payouts |
| `issuer.json` | Controls the demo asset's Core freeze policy |
| `keeper.json` | Signs only the delegated merge and settlement methods |

The launcher registers token storage and funds Core storage for these accounts.
**Wallet & security** shows the remaining Core storage budget and accepts a
top-up in NEAR. This budget is separate from the lending asset.

Generate a holder encryption key in **Wallet & security** before receiving
private funds. Export an encrypted backup, confirm that it was saved, then
register the key. The wallet signing credential and the encryption backup are
different files. Save a fresh encrypted backup after creating a broker key or
an agreement draft. Reloading the page ends the private in-memory session;
restore the encrypted backup before continuing.

## Fund a vault and agree a loan

The following example uses human-readable TEST amounts; the token has six
decimal places. The lender and borrower each start with 1,000 TEST.

1. As the broker, open **Vaults & brokers** and create an open-ended
   vault. Choose the asset limit, share scale, transfer policy, checkpoint
   interval and disclosure policy before accepting lender deposits.
2. Prepare a broker key for that vault. Export and confirm the new encrypted
   wallet backup in Security, then return to the same vault and key ID to
   register the broker. Set a debt ceiling of at least 800 TEST.
3. As the lender, open **Vaults**, send 1,000 TEST to create a public claim, then
   deposit the claim into the broker's vault. Check the finalized share balance.
4. As the borrower, register and back up the holder key. Send 100 TEST into a
   public claim using the lender workspace's deposit form, then switch to the
   borrower workspace and shield that claim in **Private balance**.
5. As the broker, draw 800 TEST in **Operations**. Draw amounts are
   public. The funds enter the broker inbox; funding preparation merges the
   inbox when the spending balance needs it.
6. In **Loan book**, prepare a private agreement for the borrower:
   principal 600 TEST, initial amount owed 660 TEST, periodic payment 220 TEST,
   and three payments. Choose a positive payment interval and a grace period.
   Use loan-auditor key ID `1` and the 64-character `loanAuditorKey.point`
   value from `.local/demo/public.json`.
7. Publish the proposal and download its exchange package. Export a fresh
   encrypted broker backup containing the agreement draft. Give the borrower
   the exchange package, which contains the encrypted agreement and recovery
   data, not the broker's private wallet material.
8. In the borrower's **Agreements** workspace, import the proposal package,
   decrypt its preview, check the terms and vault disclosure policy, then
   authorize the proposal. The preview is checked against finalized Core data.
9. As the broker, select that authorized proposal and prepare funding. Wait for
   proof generation, wallet signing and final confirmation. The borrower
   receives the principal in the confidential inbox.

Changing the agreement requires a new proposal. A proposal can be revoked
before funding. Losing its private draft does not authorize reconstructing a
different agreement under the same ciphertexts; revoke it and agree new terms.

## Repay, settle and withdraw

1. As the borrower, pay one regular installment of 220 TEST. The wallet merges
   incoming funds when needed, confirms that merge, and builds a fresh proof.
2. Use **Pay in full** for the remaining 440 TEST. A regular payment equal to
   the complete amount owed is rejected; the full-payment operation closes the
   loan and proves the remaining owed and principal values are zero.
3. As the broker, settle 860 TEST back to the vault. The first 800 TEST repays
   public broker debt; the remaining 60 TEST becomes recognized vault yield.
   The vault now has 1,060 TEST available in this example.
4. Delete the paid loan's display record and close the zero-balance broker
   account. Its immutable terminal records remain available for audit.
5. As the lender, redeem the remaining shares. Redemption creates a public
   claim. In **Claims & payouts**, reserve a payout to the registered recipient
   and finalize its recorded result. Check the finalized token balance.

Partial redemption also supports an exact asset amount with a maximum-share
guard. A final redemption requires every broker to be closed or to supply a
current zero-balance closure package. When more than four live brokers remain,
close them sequentially before the final redemption.

The regular/full repayment proofs are computed locally. The measured v4
desktop browser run took about three minutes per large proof and allocated
about 1.72 GB of WASM linear memory, plus cached artifacts. Keep the page open
while proving. A pending transaction is not a completed payment.

When a submitted transaction remains unresolved, use **Check transaction status**
in its action feedback. This reads the original transaction without resubmitting
it. A failed or unavailable status read keeps that action locked. Keep its public
transaction hash when investigating an interrupted session; do not infer failure
from a timeout or initiate a replacement payment without checking finalized state.

## Audit and loss handling

Connect the auditor account and restore `.local/demo/auditor-backup.json`
using the passphrase in its separate owner-only file. Enter the loan ID in
**Loan exports**, then explicitly load and decrypt the authorized view. JSON
export is a separate action. Loan audit also works after the loan leaves the
active index. The demo backup contains the configured loan, issuer and token
auditor keys; production roles should receive only their intended keys.

The token-audit workspace reconstructs one holder or broker mirror using the
selected asset-level auditor key. A loan-auditor key alone does not grant that
scope. The issuer/controller identities and token trust policy are shown in
the application; the demo controller is a test policy authority.

Broker impairment and default change public risk status. Required accounting
blocks new risk and share pricing until reconciliation completes at the
published cadence. Default becomes eligible only after the due date plus grace
period has passed. Reconciliation proves the aggregate loss and provision;
it does not publish individual principal amounts. A one-loan cohort can still
reveal an amount through the public aggregate. There is no collateral or
first-loss insurance in this credit model.

For automatic settlement, use the broker-only encrypted backup and restricted
function-call credential described in [README.md](../README.md#keeper-operation).
Retain the keeper journal across restarts. An unknown outgoing token result
stays reserved; a timeout never authorizes a refund or a second payment.

## Repeat the connected product checks

With Chromium installed and a freshly launched demo, run `pnpm validate:product`
from the repository root. It drives the rendered forms using separate lender,
broker, borrower, recipient and auditor sessions. Every write passes through
the application wallet; read-only RPC checks verify the resulting finalized
state and deployed code hash.

The run covers encrypted backup creation/restore, storage funding, vault
deposit, broker draw, agreement exchange/authorization, funding, confidential
spending, both repayment modes, settlement, archival, closure, redemption,
payout finalization and historical audit. Large browser proofs make this a
long-running check. Public transaction evidence is written to
`.artifacts/product-validation.json`; encrypted test backups and their separate
passphrase file stay under owner-only `.local/demo/product-validation/`.

If a long browser run is interrupted after borrower authorization but before funding, keep the same sandbox running and use `pnpm validate:product --resume-funding`. This mode validates the locally recorded final receipt evidence, deployment pins and current unfunded state, restores the encrypted wallets, revokes the old proposal and obtains fresh authorization through the UI. Old transaction outcomes may already be pruned from sandbox RPC; the recorded evidence and Core recovery history must be retained. It refuses an already funded loan and does not resume arbitrary payout or repayment states.
