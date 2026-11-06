/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_NETWORK_ID?: string
  readonly VITE_CORE_ACCOUNT_ID?: string
  readonly VITE_TOKEN_ACCOUNT_ID?: string
  readonly VITE_RPC_URL?: string
  readonly VITE_CRYPTO_PROFILE_HASH?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
