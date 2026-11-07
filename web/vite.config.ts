import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  resolve: {
    // Wallet Selector's Meteor module still ships safe-buffer. Resolve the
    // Node builtin to the browser implementation before that module evaluates.
    alias: { buffer: 'buffer/' },
  },
  define: { global: 'globalThis' },
  // Wallet Selector's optimized Meteor dependency evaluates safe-buffer's
  // Node-style global before Vite's module graph reaches the app entrypoint.
  // Keep the same browser global in the esbuild pre-bundle as in production.
  optimizeDeps: {
    esbuildOptions: {
      define: { global: 'globalThis' },
    },
  },
  server: {
    port: 5174,
    strictPort: false,
  },
  build: {
    target: 'es2022',
  },
})
