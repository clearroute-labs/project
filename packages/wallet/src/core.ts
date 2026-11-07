export type Arguments = Record<string, unknown>;
export interface FinalizedBlock { hash: string; height: number; }
export interface NearRpc extends CoreReadRpc {}

/** Structural contracts keep this low-level adapter usable before the wallet
 * package's concrete source files are linked into a browser worktree.  The
 * production Keyring/ProofBuilder/HistoryRecovery satisfy these interfaces. */
export interface CryptoExecutor {
  execute<T>(method: string, params: unknown, options?: { artifactName?: string; signal?: AbortSignal }): Promise<T>;
}
export interface Keyring {}
export interface ProofBuilder {}
export interface HistoryRecovery {}
export interface OperationContext {
  network_id: number[]; core_account: number[]; asset_id: number[]; operation_id: number[];
  vault_id: number[]; broker_id: number[]; loan_id: number[]; proposal_id: number[];
  expected_versions: string[]; authorization_epochs: string[]; expiry: string;
}
export interface ProvenOperation {
  statement: unknown;
  envelope: { context_digest: string; proof: string; statement_kind: string | number; public_inputs: string[]; verifying_key_hash: string; profile_hash: string };
}

function proofBytes(value: string, name: string): number[] {
  if (!/^(?:[a-f\d]{2})+$/i.test(value)) throw new TypeError(`${name} must be canonical hex bytes`);
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 2) bytes.push(Number.parseInt(value.slice(index, index + 2), 16));
  return bytes;
}

function proofJson(value: unknown): number[] {
  return [...new TextEncoder().encode(JSON.stringify(value))];
}

function proofArguments(operation: ProvenOperation): Record<string, unknown> {
  const kindIds: Record<string, number> = { KeyPossession: 1, PublicConversion: 2, ConfidentialTransfer: 3, Origination: 4, Repayment: 5, Reconciliation: 6, ZeroBalance: 7, Ownership: 8 };
  const kind = typeof operation.envelope.statement_kind === 'number'
    ? operation.envelope.statement_kind
    : kindIds[operation.envelope.statement_kind] ?? (() => { throw new TypeError('Unknown proof statement kind'); })();
  return {
    statement: proofJson(operation.statement),
    context: proofBytes(operation.envelope.context_digest, 'proof context'),
    proof: proofBytes(operation.envelope.proof, 'proof'),
    statement_kind: kind,
    // Core derives the public-input slots from the canonical statement and
    // deployment profile. Repeating them in the call payload only inflates
    // transactions and creates a second source of truth.
    public_inputs: [],
    verifying_key_hash: proofBytes(operation.envelope.verifying_key_hash, 'verifying key hash'),
    profile_hash: proofBytes(operation.envelope.profile_hash, 'profile hash'),
  };
}

/**
 * The read side of CoreWallet is deliberately small.  Keeping it injectable
 * makes the same proof/context adapter usable by the browser worker, the
 * native keeper, and deterministic tests without duplicating JSON-RPC logic.
 */
export interface CoreReadRpc {
  finalizedBlock(signal?: AbortSignal): Promise<FinalizedBlock>;
  viewAt<T>(block: FinalizedBlock, accountId: string, method: string, args?: Arguments, signal?: AbortSignal): Promise<T>;
}

export interface CoreWalletConfiguration {
  networkId: string;
  coreAccountId: string;
  assetId: string;
  profileHash: string;
  manifestHash?: string;
}

export interface ProofContextRequest {
  operation: string;
  primaryId?: string;
  accountId?: string;
  destination?: string;
  brokerId?: string;
  checkpointId?: string;
  action?: 'Impair' | 'Unimpair' | 'Default';
  amount?: string;
}

export interface RecoveryRecordView {
  event_id: string;
  operation: string;
  subject_key: string;
  subject_sequence: string;
  block_timestamp: string;
  statement?: number[];
  key_ids: string[];
  versions: string[];
  origin_subject_key?: string;
  origin_subject_sequence?: string;
  metadata: unknown;
}

export interface RecoveryHistoryPage {
  records: RecoveryRecordView[];
  next_cursor?: string;
  end_cursor: string;
}

export interface CoreProofContext {
  operation: string;
  assetAccount: string;
  networkId: string;
  profileHash: string;
  manifestHash: string;
  ids: string[];
  accountIds: string[];
  versions: string[];
  ciphertexts: string[];
  commitments: string[];
  publicValues: string[];
  stateDigest: string;
  statementKind?: number;
  statement: string;
  publicInputs: string[];
  verifyingKeyHash: string;
  operationContext: OperationContext;
  /** Finalized block used for every field in this view. */
  block: FinalizedBlock;
}

export interface CoreWalletDependencies {
  crypto: CryptoExecutor;
  keys: Keyring;
  proofs: ProofBuilder;
  recovery?: HistoryRecovery;
}

type WireProofContext = {
  operation?: unknown;
  asset_account?: unknown;
  network_id?: unknown;
  profile_hash?: unknown;
  verifier_manifest_hash?: unknown;
  ids?: unknown;
  account_ids?: unknown;
  versions?: unknown;
  ciphertexts?: unknown;
  commitments?: unknown;
  public_values?: unknown;
  state_digest?: unknown;
  statement_kind?: unknown;
  statement?: unknown;
  public_inputs?: unknown;
  verifying_key_hash?: unknown;
  operation_context?: unknown;
};

function fail(message: string): never { throw new Error(`Invalid Core proof context: ${message}`); }

function text(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) return fail(`${name} must be a non-empty string`);
  return value;
}

function decimal(value: unknown, name: string): string {
  if (typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value);
  return fail(`${name} must be a canonical unsigned integer`);
}

function bytes(value: unknown, name: string): number[] {
  if (!Array.isArray(value) || value.some(item => !Number.isInteger(item) || item < 0 || item > 255)) return fail(`${name} must be a byte array`);
  return value as number[];
}

function hex(value: unknown, name: string): string {
  return bytes(value, name).map(item => item.toString(16).padStart(2, '0')).join('');
}

function stringList(value: unknown, name: string): string[] {
  if (!Array.isArray(value)) return fail(`${name} must be an array`);
  return value.map((item, index) => text(item, `${name}[${index}]`));
}

function decimalList(value: unknown, name: string): string[] {
  if (!Array.isArray(value)) return fail(`${name} must be an array`);
  return value.map((item, index) => decimal(item, `${name}[${index}]`));
}

function safeKind(value: unknown, name: string): number {
  const encoded = decimal(value, name);
  const result = Number(encoded);
  if (!Number.isSafeInteger(result)) return fail(`${name} is outside the JavaScript safe integer range`);
  return result;
}

function bytesList(value: unknown, name: string): string[] {
  if (!Array.isArray(value)) return fail(`${name} must be an array`);
  return value.map((item, index) => hex(item, `${name}[${index}]`));
}

function asId(value: string | undefined, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (!/^(0|[1-9]\d*)$/.test(value)) throw new TypeError(`${field} must be a canonical decimal string`);
  return value;
}

function operationContext(value: unknown): OperationContext {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail('operation_context must be an object');
  const context = value as Record<string, unknown>;
  const id = (name: string): number[] => {
    const value = context[name];
    if (!Array.isArray(value) || value.length !== 32 || value.some(item => !Number.isInteger(item) || item < 0 || item > 255)) return fail(`${name} must contain 32 bytes`);
    return value as number[];
  };
  const versions = context.expected_versions;
  const epochs = context.authorization_epochs;
  if (!Array.isArray(versions) || versions.length !== 8) return fail('expected_versions must contain eight entries');
  if (!Array.isArray(epochs) || epochs.length !== 4) return fail('authorization_epochs must contain four entries');
  return {
    network_id: id('network_id'), core_account: id('core_account'), asset_id: id('asset_id'), operation_id: id('operation_id'),
    vault_id: id('vault_id'), broker_id: id('broker_id'), loan_id: id('loan_id'), proposal_id: id('proposal_id'),
    expected_versions: versions.map((item, index) => decimal(item, `expected_versions[${index}]`)),
    authorization_epochs: epochs.map((item, index) => decimal(item, `authorization_epochs[${index}]`)),
    expiry: decimal(context.expiry, 'expiry'),
  };
}

function contextArgs(request: ProofContextRequest): Record<string, unknown> {
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(request.operation)) throw new TypeError('Invalid Core proof operation');
  const args: Record<string, unknown> = { operation: request.operation };
  const primaryId = asId(request.primaryId, 'primaryId');
  const brokerId = asId(request.brokerId, 'brokerId');
  const checkpointId = asId(request.checkpointId, 'checkpointId');
  if (primaryId !== undefined) args.primary_id = primaryId;
  if (request.accountId !== undefined) args.account_id = request.accountId;
  if (request.destination !== undefined) args.destination = request.destination;
  if (brokerId !== undefined) args.broker_id = brokerId;
  if (checkpointId !== undefined) args.checkpoint_id = checkpointId;
  if (request.action !== undefined) args.action = request.action;
  if (request.amount !== undefined) {
    if (!/^(0|[1-9]\d*)$/.test(request.amount)) throw new TypeError('amount must be a canonical decimal string');
    args.amount = request.amount;
  }
  return args;
}

function recoveryPage(value: unknown): RecoveryHistoryPage {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail('recovery page must be an object');
  const page = value as Record<string, unknown>;
  if (!Array.isArray(page.records)) return fail('recovery records must be an array');
  const records = page.records.map((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return fail(`recovery record ${index} must be an object`);
    const record = item as Record<string, unknown>;
    const result: RecoveryRecordView = {
      event_id: decimal(record.event_id, `records[${index}].event_id`),
      operation: text(record.operation, `records[${index}].operation`),
      subject_key: text(record.subject_key, `records[${index}].subject_key`),
      subject_sequence: decimal(record.subject_sequence, `records[${index}].subject_sequence`),
      block_timestamp: decimal(record.block_timestamp, `records[${index}].block_timestamp`),
      key_ids: decimalList(record.key_ids, `records[${index}].key_ids`),
      versions: decimalList(record.versions, `records[${index}].versions`),
      metadata: record.metadata,
    };
    if (record.statement !== undefined) result.statement = bytes(record.statement, `records[${index}].statement`);
    if (record.origin_subject_key !== undefined) result.origin_subject_key = text(record.origin_subject_key, `records[${index}].origin_subject_key`);
    if (record.origin_subject_sequence !== undefined) result.origin_subject_sequence = decimal(record.origin_subject_sequence, `records[${index}].origin_subject_sequence`);
    return result;
  });
  const result: RecoveryHistoryPage = {
    records,
    end_cursor: decimal(page.end_cursor, 'end_cursor'),
  };
  if (page.next_cursor !== null && page.next_cursor !== undefined) result.next_cursor = decimal(page.next_cursor, 'next_cursor');
  return result;
}

/**
 * Finality-pinned Core reads plus the browser/native proof dependencies.  It
 * intentionally does not expose a generic RPC call method: callers must use a
 * named context/history read or an injected proof builder, keeping private
 * witnesses out of network arguments by construction.
 */
export class CoreWallet {
  readonly recovery: HistoryRecovery | undefined;

  constructor(
    readonly rpc: CoreReadRpc,
    readonly configuration: CoreWalletConfiguration,
    readonly crypto: CryptoExecutor,
    readonly keys: Keyring,
    readonly proofs: ProofBuilder,
    recovery?: HistoryRecovery,
  ) {
    if (!configuration.coreAccountId || !configuration.networkId || !configuration.assetId) throw new TypeError('CoreWallet requires deployment identity');
    if (!/^[a-f0-9]{64}$/.test(configuration.profileHash)) throw new TypeError('CoreWallet requires a canonical profile hash');
    this.recovery = recovery;
  }

  static fromNearRpc(rpc: NearRpc, configuration: CoreWalletConfiguration, dependencies: CoreWalletDependencies): CoreWallet {
    return new CoreWallet(rpc, configuration, dependencies.crypto, dependencies.keys, dependencies.proofs, dependencies.recovery);
  }

  /** Read one named public Core view at a single finalized block. */
  async read<T>(method: string, args: Arguments = {}, signal?: AbortSignal): Promise<{ value: T; block: FinalizedBlock }> {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(method)) throw new TypeError('Invalid Core view method');
    const block = await this.rpc.finalizedBlock(signal);
    const value = await this.rpc.viewAt<T>(block, this.configuration.coreAccountId, method, args, signal);
    return { value, block };
  }

  async getProofContext(request: ProofContextRequest, signal?: AbortSignal): Promise<CoreProofContext | undefined> {
    const block = await this.rpc.finalizedBlock(signal);
    const raw = await this.rpc.viewAt<WireProofContext>(block, this.configuration.coreAccountId, 'get_proof_context', contextArgs(request), signal);
    if (raw === null || raw === undefined) return undefined;
    const result: CoreProofContext = {
      operation: text(raw.operation, 'operation'),
      assetAccount: text(raw.asset_account, 'asset_account'),
      networkId: text(raw.network_id, 'network_id'),
      profileHash: hex(raw.profile_hash, 'profile_hash'),
      manifestHash: hex(raw.verifier_manifest_hash, 'verifier_manifest_hash'),
      ids: decimalList(raw.ids, 'ids'),
      accountIds: stringList(raw.account_ids, 'account_ids'),
      versions: decimalList(raw.versions, 'versions'),
      ciphertexts: bytesList(raw.ciphertexts, 'ciphertexts'),
      commitments: bytesList(raw.commitments, 'commitments'),
      publicValues: decimalList(raw.public_values, 'public_values'),
      stateDigest: hex(raw.state_digest, 'state_digest'),
      statement: new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes(raw.statement, 'statement'))),
      publicInputs: bytesList(raw.public_inputs, 'public_inputs'),
      verifyingKeyHash: hex(raw.verifying_key_hash, 'verifying_key_hash'),
      operationContext: operationContext(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes(raw.operation_context, 'operation_context'))))),
      block,
    };
    if (raw.statement_kind !== null && raw.statement_kind !== undefined) result.statementKind = safeKind(raw.statement_kind, 'statement_kind');
    if (result.profileHash !== this.configuration.profileHash) throw new Error('Core proof context profile does not match the deployment');
    if (this.configuration.manifestHash && result.manifestHash !== this.configuration.manifestHash) throw new Error('Core proof context manifest does not match the deployment');
    return result;
  }

  async listRecoveryHistory(subjectKey: string, cursor = '0', limit = 64, signal?: AbortSignal): Promise<RecoveryHistoryPage> {
    if (!subjectKey || subjectKey.length > 128) throw new TypeError('Invalid recovery subject key');
    if (!/^(0|[1-9]\d*)$/.test(cursor)) throw new TypeError('Recovery cursor must be a canonical decimal string');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 256) throw new RangeError('Recovery limit must be between 1 and 256');
    const block = await this.rpc.finalizedBlock(signal);
    const raw = await this.rpc.viewAt<unknown>(block, this.configuration.coreAccountId, 'list_recovery_history', { subject_key: subjectKey, cursor, limit }, signal);
    return recoveryPage(raw);
  }

  /** Build a proof using the exact finalized context returned by Core. */
  async prove<T extends ProvenOperation>(request: ProofContextRequest, build: (context: OperationContext) => Promise<T>, signal?: AbortSignal): Promise<{ context: CoreProofContext; operation: T; args: Record<string, unknown> }> {
    const context = await this.getProofContext(request, signal);
    if (!context) throw new Error(`Core has no proof context for ${request.operation}`);
    const operation = await build(context.operationContext);
    return { context, operation, args: proofArguments(operation) };
  }
}

