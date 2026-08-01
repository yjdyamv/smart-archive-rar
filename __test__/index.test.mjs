import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createReadStream } from 'node:fs'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createArchive } from '../index.js'

const RAR5_SIG = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00])

function tempDir() {
  return mkdtempSync(join(tmpdir(), 'sar-test-'))
}

function readFileHead(path, n = 8) {
  return new Promise((resolve, reject) => {
    const chunks = []
    const s = createReadStream(path, { start: 0, end: n - 1 })
    s.on('data', (c) => chunks.push(c))
    s.on('end', () => resolve(Buffer.concat(chunks)))
    s.on('error', reject)
  })
}

test('creates a RAR5 archive from bytes and disk files', async () => {
  const dir = tempDir()
  try {
    writeFileSync(join(dir, 'disk.txt'), 'from disk')
    const out = join(dir, 'out.rar')
    const res = await createArchive({
      outPath: out,
      level: 5,
      entries: [
        { kind: 'bytes', name: 'notes/a.bin', data: Buffer.alloc(100_000, 7) },
        { kind: 'file', path: join(dir, 'disk.txt'), name: 'docs/disk.txt' },
      ],
    })
    assert.deepEqual(res.files, [out])
    const head = await readFileHead(out)
    assert.deepEqual(head, RAR5_SIG)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('reports progress from 0 to 100%', async () => {
  const dir = tempDir()
  try {
    const events = []
    const out = join(dir, 'prog.rar')
    await createArchive(
      {
        outPath: out,
        entries: [{ kind: 'bytes', name: 'data.bin', data: Buffer.alloc(1_000_000, 3) }],
      },
      (_err, p) => events.push(p.done / p.total),
    )
    assert.ok(events.length > 0, 'no progress events')
    assert.equal(events.at(-1), 1)
    for (const [a, b] of events.slice(1).map((v, i) => [events[i], v])) {
      assert.ok(a <= b, 'progress went backwards')
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('creates multi-volume archives', async () => {
  const dir = tempDir()
  try {
    const out = join(dir, 'vol.rar')
    const res = await createArchive({
      outPath: out,
      volumeSize: 100_000,
      level: 0,
      entries: [{ kind: 'bytes', name: 'big.bin', data: Buffer.alloc(250_000, 9) }],
    })
    assert.ok(res.files.length >= 3, `expected >=3 volumes, got ${res.files.length}`)
    for (const f of res.files) {
      assert.equal((await readFileHead(f)).subarray(0, 7).toString(), 'Rar!\x1a\x07\x01')
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rejects when maxTotalBytes is exceeded', async () => {
  const dir = tempDir()
  try {
    await assert.rejects(
      createArchive({
        outPath: join(dir, 'x.rar'),
        maxTotalBytes: 1000,
        entries: [{ kind: 'bytes', name: 'a.bin', data: Buffer.alloc(2000, 1) }],
      }),
      /exceeds limit/,
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rejects missing file paths', async () => {
  const dir = tempDir()
  try {
    await assert.rejects(
      createArchive({
        outPath: join(dir, 'x.rar'),
        entries: [{ kind: 'file', path: join(dir, 'nope.txt') }],
      }),
      /cannot stat/,
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('rejects unknown entry kinds', async () => {
  const dir = tempDir()
  try {
    await assert.rejects(
      createArchive({
        outPath: join(dir, 'x.rar'),
        entries: [{ kind: 'gzip', name: 'a' }],
      }),
      /unknown entry kind/,
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
