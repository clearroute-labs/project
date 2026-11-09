import { fileURLToPath } from 'node:url'
import { defineConfig, normalizePath } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  resolve: {
    // NEAR signing dependencies use Buffer and util in the browser.
    alias: { buffer: 'buffer/', util: 'util/' },
  },
  define: {
    global: 'globalThis',
    'process.env.DEFAULT_FINALITY': JSON.stringify('near-final'),
  },
  // Keep the same browser globals in dependency pre-bundles and production.
  optimizeDeps: {
    // Discover popup dependencies before a wallet connection is in progress;
    // a late optimizer reload would discard the opener's pending request.
    include: ['@hot-labs/near-connect', '@privy-io/react-auth', '@privy-io/react-auth/extended-chains', '@privy-io/js-sdk-core', '@peerfolio/privy-near-connect/sign-page'],
    esbuildOptions: {
      define: {
        global: 'globalThis',
        'process.env.DEFAULT_FINALITY': JSON.stringify('near-final'),
      },
    },
  },
  server: {
    port: 5174,
    strictPort: false,
    fs: {
      // Block nested checkouts without blocking this project when it is itself
      // inside a worktree. Vite's workspace allow-list still excludes siblings.
      deny: ['.env', '.env.*', '*.{crt,pem,key}', '**/.git', '**/.git/**', '**/.local/**', '**/.artifacts/**', `${normalizePath(fileURLToPath(new URL('../.worktrees', import.meta.url)))}/**`, '**/.aws/**', '**/.ssh/**', '**/.codex/**', '**/.agents/**', '**/.superdesign/**'],
    },
  },
  build: {
    target: 'es2022',
  },
})
