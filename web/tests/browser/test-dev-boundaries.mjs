#!/usr/bin/env node
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile, unlink, rmdir, stat } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import path from 'node:path'

const origin = new URL(process.env.UI_BASE_URL || 'http://localhost:5174').origin
const root = fileURLToPath(new URL('../../../', import.meta.url))
const fixtures = []
const createdParents = []

async function probe(parent) {
  try { await mkdir(parent); createdParents.push(parent) }
  catch (error) { if (error.code !== 'EEXIST') throw error }
  const directory = await mkdtemp(path.join(parent, 'vite-boundary-'))
  const file = path.join(directory, 'probe.txt')
  fixtures.push({ directory, file })
  await writeFile(file, 'development boundary fixture')
  return file
}

async function expectDenied(file) {
  const response = await fetch(`${origin}/@fs/${file}`)
  assert.equal(response.status, 403, `Development server must deny ${path.relative(root, file)}.`)
}

try {
  assert.equal((await fetch(origin)).status, 200, 'The active checkout must remain accessible inside a worktree.')
  const git = path.join(root, '.git')
  await expectDenied((await stat(git)).isDirectory() ? path.join(git, 'config') : git)
  await expectDenied(path.join(root, 'web/.env.example'))
  for (const relative of ['.local', '.artifacts', '.superdesign', '.Codex', '.worktrees']) {
    await expectDenied(await probe(path.join(root, relative)))
  }
  await expectDenied(await probe(tmpdir()))
  console.log('Development file boundaries passed.')
} finally {
  // Remove only the exact temporary files/directories created by this run.
  for (const { file, directory } of fixtures.reverse()) {
    await unlink(file)
    await rmdir(directory)
  }
  for (const parent of createdParents.reverse()) await rmdir(parent)
}
