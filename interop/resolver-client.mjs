// Reverse interop: drives a started dtp-global with TrustGraph's
// @dtp/resolver-client (built dist) through every session script, using
// the client's API instead of raw frames. Not part of cargo test (no Node
// in the Rust CI).
//
//   cargo build -p dtp-server
//   node interop/resolver-client.mjs [path/to/dtp-global]
//
// Needs ../TrustGraph with packages/resolver-client/dist and
// packages/conformance/dist built. Exit code 1 when a step fails.

import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ResolverClient, ResolverError } from '../../TrustGraph/packages/resolver-client/dist/index.js'
import { loadSessions, matchFrame, requirementMet } from '../../TrustGraph/packages/conformance/dist/session-runner.js'

const here = dirname(fileURLToPath(import.meta.url))
const exe = resolve(process.argv[2] ?? join(here, '..', 'target', 'debug', process.platform === 'win32' ? 'dtp-global.exe' : 'dtp-global'))
const corpus = resolve(here, '..', '..', 'TrustGraph', 'corpus')

function freePort() {
  return new Promise((res, rej) => {
    const srv = createServer()
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => res(port))
    })
    srv.on('error', rej)
  })
}

function toml(config, port, adminPort, dataDir) {
  const model = { scope_profile: 'x.com' }
  const auth = { reads: 'open', writes: 'members' }
  const guardrails = {}
  for (const [key, value] of Object.entries(config)) {
    if (key === 'auth.reads') auth.reads = value
    else if (key === 'auth.writes') auth.writes = value
    else if (key === 'scopeProfile') model.scope_profile = value
    else if (key === 'limits.maxReachedNodes') guardrails.max_reached_nodes = value
    else if (key === 'limits.maxWalkRecords') guardrails.max_walk_records = value
    else throw new Error(`unsupported session config key ${key}`)
  }
  const section = (name, obj) => `[${name}]\n${Object.entries(obj).map(([k, v]) => `${k} = ${JSON.stringify(v)}`).join('\n')}\n`
  return [
    section('server', { listen: `127.0.0.1:${port}` }),
    section('model', model),
    section('auth', auth),
    section('guardrails', guardrails),
    section('storage', { data_dir: dataDir.replaceAll('\\', '/') }),
    section('admin', { listen: `127.0.0.1:${adminPort}` }),
  ].join('\n')
}

async function startServer(config) {
  const dir = mkdtempSync(join(tmpdir(), 'dtp-interop-'))
  const [port, adminPort] = [await freePort(), await freePort()]
  const configFile = join(dir, 'dtp-global.toml')
  writeFileSync(configFile, toml(config, port, adminPort, join(dir, 'data')))
  const child = spawn(exe, ['--config', configFile], { stdio: ['ignore', 'ignore', 'pipe'] })
  let stderr = ''
  child.stderr.on('data', (d) => (stderr += d))
  const until = Date.now() + 10_000
  while (Date.now() < until) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/readyz`)).ok) break
    } catch {}
    await new Promise((r) => setTimeout(r, 100))
  }
  const stop = () =>
    new Promise((r) => {
      child.once('exit', () => {
        rmSync(dir, { recursive: true, force: true })
        r()
      })
      child.kill()
    })
  return { url: `ws://127.0.0.1:${port}/`, stop, stderr: () => stderr }
}

function permutations(items) {
  if (items.length <= 1) return [items]
  return items.flatMap((x, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((p) => [x, ...p]))
}

const errFrame = (reqId, e) =>
  e instanceof ResolverError ? ['DTP-ERR', reqId, e.code, e.message] : ['DTP-ERR', reqId, 'error', String(e)]

/** Runs one step through the client API and returns the frames it maps to. */
async function actualFrames(client, step, pushes, wantPush) {
  const [type, ...rest] = step.send
  const frames = []
  if (type === 'EVENT') {
    const event = rest[0]
    const r = await client.publish(event)
    frames.push(['OK', event.id, r.accepted, r.message])
  } else if (type === 'DTP') {
    const [reqId, op, params] = rest
    try {
      const result = op === 'session.update' ? await client.sessionUpdate(params.defaults ?? {}) : await client.request(op, params)
      frames.push(['DTP-OK', reqId, result])
    } catch (e) {
      frames.push(errFrame(reqId, e))
    }
  } else if (type === 'REQ') {
    const [sub, ...filters] = rest
    try {
      const events = await client.req(filters)
      frames.push(...events.map((e) => ['EVENT', sub, e]), ['EOSE', sub])
    } catch (e) {
      frames.push(['CLOSED', sub, e.message])
    }
  } else {
    return undefined
  }
  if (wantPush) {
    const until = Date.now() + 3_000
    while (pushes.length === 0 && Date.now() < until) await new Promise((r) => setTimeout(r, 25))
    frames.push(...pushes.splice(0).map((p) => ['DTP-PUSH', p.topic, p.data]))
  }
  return frames
}

let failed = 0
for (const { file, session } of loadSessions(corpus)) {
  const server = await startServer(session.config)
  const client = new ResolverClient({ url: server.url, requestTimeoutMs: 5_000 })
  const pushes = []
  client.on('push', (p) => pushes.push(p))
  const counts = { passed: 0, failed: 0, skipped: 0 }
  try {
    const info = await client.info()
    const features = { capabilities: info.capabilities ?? [], gaps: info.gaps ?? [] }
    const met = (reqs) => (reqs ?? []).every((r) => requirementMet(r, features))
    for (const [index, step] of session.steps.entries()) {
      const expected = met(session.requires) && met(step.requires) ? step.expect : step.otherwise
      const wantPush = !!expected?.some((f) => f[0] === 'DTP-PUSH')
      if (!wantPush) pushes.length = 0
      const got = expected ? await actualFrames(client, step, pushes, wantPush) : undefined
      if (!got) {
        counts.skipped++
        continue
      }
      const orders = step.unordered ? permutations(got) : [got]
      const errors = orders
        .map((order) => (order.length === expected.length ? expected.flatMap((f, i) => matchFrame(order[i], f, `frame[${i}]`)) : [`expected ${expected.length} frames, got ${order.length}`]))
        .reduce((best, e) => (e.length < best.length ? e : best))
      if (errors.length === 0) counts.passed++
      else {
        counts.failed++
        console.log(`  FAIL ${session.id} step ${index}${step.note ? ` (${step.note})` : ''}\n    - ${errors.slice(0, 6).join('\n    - ')}`)
      }
    }
  } finally {
    client.close()
    await server.stop()
  }
  failed += counts.failed
  console.log(`${session.id} (${file}): ${session.steps.length} steps: ${counts.passed} passed, ${counts.failed} failed, ${counts.skipped} skipped`)
}
process.exit(failed ? 1 : 0)
