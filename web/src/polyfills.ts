import { Buffer as BrowserBuffer } from 'buffer'

// NEAR transaction serialization still uses the Buffer global in browsers.
const browserGlobal = globalThis as typeof globalThis & { Buffer?: typeof BrowserBuffer }
if (!browserGlobal.Buffer) browserGlobal.Buffer = BrowserBuffer
