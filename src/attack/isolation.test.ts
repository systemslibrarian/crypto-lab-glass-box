import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Invariant I2, enforced rather than described.
 *
 * The attack modules must not be able to read the key, the encodings, the mixing
 * bijections or the external-encoding party. In a single-process browser demo
 * there is no sandbox to lean on, so the boundary is the MODULE GRAPH: if
 * `dca.ts` cannot import `wb-gen.ts`, it cannot reach a secret however the UI is
 * wired, and a future edit that reaches for one fails here instead of quietly
 * turning the attack into a lookup.
 *
 * What IS allowed, and why each is not a hole:
 *   ../aes/*        FIPS 197. Public, and the source of the two hypotheses.
 *   ../wb/layout.js The table geometry. An attacker holding the binary can read
 *                   this off it; Chow never claims otherwise and BGE starts here.
 *   ../wb/types.js  Type declarations only, erased at build time.
 *   ../math/*       GF(2) linear algebra. No secret, no key, no encoding.
 *
 * What is forbidden:
 *   ../wb/wb-gen.js     knows the key and every encoding
 *   ../wb/remote-enc.js holds the external encodings (invariant I7)
 *   ../wb/rng.js        the randomness the encodings are drawn from
 *   ../wb/encoding.js   constructs the nibble bijections
 *   ../wb/wb-run.js     would let the attack re-run the program with a chosen
 *                       input outside the harness's observability rules
 */

const here = dirname(fileURLToPath(import.meta.url));

const FORBIDDEN = ['../wb/wb-gen.js', '../wb/remote-enc.js', '../wb/rng.js', '../wb/encoding.js', '../wb/wb-run.js'];

const ALLOWED = new Set([
  '../aes/aes-ref.js',
  '../aes/gf.js',
  '../wb/layout.js',
  '../wb/types.js',
  '../math/gf2.js',
  './dca.js',
  './bge.js',
]);

function attackSources(): string[] {
  return readdirSync(here).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'));
}

function importsOf(source: string): string[] {
  const out: string[] = [];
  // Static imports, type-only imports, and dynamic import() alike.
  const pattern = /(?:\bfrom\s*|\bimport\s*\()\s*['"]([^'"]+)['"]/g;
  for (let match = pattern.exec(source); match !== null; match = pattern.exec(source)) out.push(match[1]);
  return out;
}

describe('invariant I2: the attack cannot import a secret', () => {
  it('finds the attack modules it is supposed to be guarding', () => {
    const files = attackSources();
    expect(files.sort()).toEqual(['bge.ts', 'dca.ts']);
  });

  it.each(attackSources())('%s imports nothing that knows a secret', (file) => {
    const source = readFileSync(join(here, file), 'utf8');
    const imports = importsOf(source);
    expect(imports.length).toBeGreaterThan(0);
    for (const specifier of imports) {
      expect(FORBIDDEN, `${file} imports ${specifier}`).not.toContain(specifier);
      expect(ALLOWED.has(specifier), `${file} imports ${specifier}, which is not on the allow-list`).toBe(true);
    }
  });

  it.each(attackSources())('%s never names the key, the wires or the bijections', (file) => {
    const source = readFileSync(join(here, file), 'utf8');
    // Strip block and line comments: the modules DISCUSS the key at length, on
    // purpose. What must not appear is code that reads one.
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const forbidden of ['buildNetwork', 'createRemoteParty', 'outputByteBijection', 'seededRng', 'systemRng']) {
      expect(code, `${file} calls ${forbidden}`).not.toContain(forbidden);
    }
  });

  it('the guard bites: a fabricated import of the generator would be caught', () => {
    // Proving the oracle works, per the mutation discipline. The check is the
    // same function the real files go through.
    const fabricated = `import { buildNetwork } from '../wb/wb-gen.js';\nexport const x = buildNetwork;\n`;
    const imports = importsOf(fabricated);
    expect(imports).toEqual(['../wb/wb-gen.js']);
    expect(FORBIDDEN).toContain(imports[0]);
    expect(ALLOWED.has(imports[0])).toBe(false);
  });

  it('...and so would a dynamic import', () => {
    const fabricated = `export const load = () => import('../wb/remote-enc.js');\n`;
    expect(importsOf(fabricated)).toEqual(['../wb/remote-enc.js']);
  });
});
