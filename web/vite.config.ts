import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  resolve: {
    // Wallet dependencies use safe-buffer and generate-function's util.format.
    // Both need their browser implementations in development and production.
    alias: { buffer: 'buffer/', util: 'util/' },
  },
  define: {
    global: 'globalThis',
    'process.env.DEFAULT_FINALITY': JSON.stringify('near-final'),
  },
  // Wallet Selector's optimized Meteor dependency evaluates safe-buffer's
  // Node-style global before Vite's module graph reaches the app entrypoint.
  // Keep the same browser global in the esbuild pre-bundle as in production.
  optimizeDeps: {
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
  },
  build: {
    target: 'es2022',
  },
})
