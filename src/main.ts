/**
 * Glass Box: a Chow-style white-box AES-128, traced and broken in the browser.
 *
 * The page is one pipeline in seven acts. Build a program, trace it, attack it,
 * change where the external encodings live and watch what that does and does not
 * change, then attack the same tables algebraically instead.
 *
 * Everything expensive runs in `lab.worker.ts`. This file is the wiring: it
 * builds the DOM, keeps one small piece of state per act, and writes what the
 * worker measured. It computes nothing cryptographic, which is why every number
 * on screen can be traced to a worker report rather than to a literal here.
 */

import './styles.css';
import {
  DEFAULT_TRACES,
  LAB_FAILURE_CODES,
  MAX_TRACES,
  MIN_TRACES,
  TRACE_BUDGET_BYTES,
  type BgeReport,
  type BuildReport,
  type DcaReport,
  type HeatmapReport,
  type LabResponse,
  type RequestBody,
  type TraceReport,
} from './protocol.js';
import { BGE_FAILURE_CODES, PUBLISHED_WORK_FACTORS } from './attack/bge.js';
import { TARGET_LABELS } from './attack/dca.js';
import type { AttackSurface, DcaTarget, EncodingPlacement } from './wb/types.js';
import { createDiagram } from './ui/diagram.js';
import {
  button,
  checkbox,
  clear,
  definitionList,
  details,
  el,
  field,
  figure,
  list,
  panel,
  radioGroup,
  scroller,
  section,
  select,
  status,
  table,
  verdict,
  type Cell,
  type VerdictTone,
} from './ui/dom.js';
import { drawCurves, drawFocusHeatmap, drawPeaksPerGuess, drawTraceHeatmap } from './ui/plots.js';

// ── the worker client ───────────────────────────────────────────────────────

const worker = new Worker(new URL('./lab.worker.ts', import.meta.url), {
  type: 'module',
});
let nextId = 1;

interface Pending {
  resolve(value: Extract<LabResponse, { kind: string }>): void;
  reject(reason: Error & { code?: string }): void;
  onProgress(phase: string, done: number, total: number): void;
}
const pending = new Map<number, Pending>();

worker.addEventListener('message', (event: MessageEvent<LabResponse>) => {
  const message = event.data;
  const entry = pending.get(message.id);
  if (!entry) return;
  if (message.kind === 'progress') {
    entry.onProgress(message.phase, message.done, message.total);
    return;
  }
  pending.delete(message.id);
  if (message.kind === 'failure') {
    const error = new Error(message.message) as Error & { code?: string };
    error.code = message.code;
    entry.reject(error);
    return;
  }
  entry.resolve(message);
});

function ask<T extends { kind: string }>(
  request: RequestBody,
  onProgress: (phase: string, done: number, total: number) => void = () => {},
): Promise<T> {
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, {
      resolve: resolve as unknown as Pending['resolve'],
      reject,
      onProgress,
    });
    worker.postMessage({ ...request, id });
  });
}

// ── formatting ─────────────────────────────────────────────────────────────

const byteHex = (v: number): string => v.toString(16).padStart(2, '0');
const group4 = (hex: string): string => (hex.match(/.{1,8}/g) ?? []).join(' ');
const bytesHuman = (n: number): string =>
  n >= 1048576 ? `${(n / 1048576).toFixed(2)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} bytes`;
const count = (n: number): string => n.toLocaleString('en-US');
const percent = (x: number): string => `${(x * 100).toFixed(1)}%`;

// ── the state each act needs from the one before ────────────────────────────

interface LabState {
  placement: EncodingPlacement;
  seed: string;
  traces: number;
  surface: AttackSurface;
  inputTargets: DcaTarget[];
  bitChoice: 'all' | number;
  bgeRound: number;
  bgeColumn: number;
  build: BuildReport | null;
  trace: TraceReport | null;
  dca: DcaReport | null;
  inspectByte: number;
  inspectGuess: 'recovered' | 'wrong';
  /** What a rebuild invalidated, so the page can say so rather than just blank. */
  retired: { traces: number; attacked: boolean; reason: string } | null;
  /**
   * How many times each act has completed this session.
   *
   * Printed in each status line, and not only for tidiness: several of this
   * page's verdicts read the same after a re-run as before it -- "IT IS AES-128"
   * does not change when you rebuild with a different seed -- so without a
   * counter neither a reader nor a test can tell a finished re-run from a click
   * that did nothing. The claims suite waits on these.
   */
  runs: { build: number; trace: number; dca: number; bge: number };
  /** One row per (placement, surface) the reader has actually run. */
  log: {
    placement: EncodingPlacement;
    surface: AttackSurface;
    traces: number;
    targets: readonly DcaTarget[];
    correctCount: number;
    complete: boolean;
    confident: number;
    confidentWrong: number;
    tables: number;
    bytes: number;
    traceBits: number;
    recovers: 'key' | 'last-round-key';
    hypothesisValid: boolean;
  }[];
  bge: BgeReport | null;
}

const state: LabState = {
  placement: 'none',
  seed: '',
  traces: DEFAULT_TRACES,
  surface: 'input',
  inputTargets: ['sbox-output'],
  bitChoice: 'all',
  bgeRound: 1,
  bgeColumn: 0,
  build: null,
  trace: null,
  dca: null,
  inspectByte: 0,
  inspectGuess: 'recovered',
  retired: null,
  runs: { build: 0, trace: 0, dca: 0, bge: 0 },
  log: [],
  bge: null,
};

/** The margin above which this lab calls a recovered byte confident. Measured, not chosen. */
export const CONFIDENCE_MARGIN = 0.15;

function bitsSelected(): number[] {
  return state.bitChoice === 'all' ? [0, 1, 2, 3, 4, 5, 6, 7] : [state.bitChoice];
}

function targetsSelected(): DcaTarget[] {
  return state.surface === 'input' ? [...state.inputTargets] : ['last-round'];
}

const PLACEMENT_LABELS: Record<EncodingPlacement, string> = {
  none: 'no external encodings',
  'compiled-in': 'compiled into the program',
  'remote-both': 'remote, both sides',
  'remote-input': 'remote, input side only',
  'remote-output': 'remote, output side only',
};

// ── shells the acts fill in ─────────────────────────────────────────────────

const app = document.getElementById('app');
if (!app) throw new Error('the page must mount at id="app"');

const main = el('main', { class: 'lab' });

function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title' }, ['Glass Box']),
      el('p', { class: 'cl-hero-sub' }, ['Chow et al. white-box AES · DCA (Bos et al. 2016) · BGE (2004)']),
      el('p', { class: 'cl-hero-desc' }, [
        'Builds a real Chow table-network AES-128 from a key you choose, has the program record its own table lookups, and runs differential computation analysis on that trace until the key comes back out.',
      ]),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label' }, ['WHY IT MATTERS']),
      el('p', { class: 'cl-hero-why-text' }, [
        'Software that has to decrypt on hardware its owner controls — a streaming client, a payment app, a licence check — ships the key inside the binary. White-box cryptography is the attempt to make that survivable. Chow’s design is the one everything else is built on, and two published attacks take the key out of it: one needs a few hundred execution traces, the other needs none.',
      ]),
    ]),
  ]);
}

app.append(hero(), main);
// ── Scope: what is real, what is not, and what this does not prove ──────────

/**
 * NEG-1, the negative claim, in one place so the scope card and the fixture
 * quote the same sentence and cannot drift apart.
 */
const NEG_1 =
  'Holding Chow’s external encodings outside the program stops this trace-based attack on this construction; it does not make the construction’s own encodings secret. The tables still give their internal and boundary encodings up to an algebraic attack that uses no traces at all.';

function negClaim(where: 'scope' | 'fixture'): HTMLElement {
  return el('div', { class: 'neg-claim', 'data-negative-claim': 'NEG-1', 'data-where': where }, [
    el('span', { class: 'neg-claim-label' }, ['WHAT THIS DOES NOT BUY — NEG-1']),
    el('p', { class: 'neg-claim-text' }, [NEG_1]),
  ]);
}

function scopeSection(): HTMLElement {
  const node = section(
    'scope',
    'Before anything else',
    'What is real here, and what it does not prove',
    'This lab builds real cryptography and really breaks it. It is still a teaching demo, and the difference between what it runs and what an attacker runs matters enough to put first.',
  );
  const body = panel('scope-panel');
  body.append(
    el('h3', {}, ['Real']),
    list([
      'The cipher. AES-128 exactly as FIPS 197 defines it, with the S-box assembled from the GF(2⁸) inverse and the section 5.1.1 affine map rather than pasted from a table.',
      'The white-box construction. Chow’s table network at full size: T-boxes with the round key folded in, Tyᵢ tables for MixColumns, nibble XOR tables, random 4-bit internal encodings on every wire, and the 8×8 and 32×32 GF(2) mixing bijections of his section 3.2. Nothing is left out to make a picture simpler.',
      'The check. Every program this page builds is compared against WebCrypto — an independent AES — on random blocks, and against the FIPS 197 Appendix C.1 vector, before you are told it works.',
      'The attack. Difference of means over a software execution trace, exactly the distinguisher Bos et al. use, scoring all 4,096 hypotheses with no knowledge of the encodings.',
      'The algebra. Step A1 of Billet, Gilbert and Ech-Chatbi’s attack, run live on the tables.',
    ]),
    el('h3', {}, ['Not the real thing']),
    list([
      'The trace comes from the program instrumenting itself. Real DCA captures the same kind of data from a foreign binary with dynamic binary instrumentation — Intel PIN, Valgrind, a debugger — which a browser cannot run. What is recorded here is the output of every table lookup, in execution order, which is the quantity those tools give you.',
      'The external encodings are 128×128 GF(2) mixing bijections. Chow specifies external encodings as mixing bijections on the whole block, so this is one of the forms he gives; an arbitrary bijection on 128 bits is not a thing that can be stored.',
      'This is not an obfuscated commercial white-box. No control-flow flattening, no anti-debug, no masking. Those raise the cost of getting a trace; the published attacks assume you got one.',
    ]),
    el('h3', {}, ['What it does not prove']),
    list([
      'Nothing here is a statement about white-box schemes in general. Every result on this page is about the constructions this page builds and the papers it cites.',
      'It does not show that wider encodings would be safe. Rivain and Wang broke encodings wider than 4 bits, including a byte-encoded implementation that plain DCA had failed on. Nibble width is why FIRST-ORDER DCA works here, not the boundary of the attack family.',
      'A recovery that fails is not a proof of security. It is one measurement, of one instance, at one trace count, with one distinguisher.',
      'The recovery rates this page reports were measured on this generator. They are not properties of Chow’s construction, and they are not the figures from any paper. Where a paper’s figure appears it is attributed.',
    ]),
    negClaim('scope'),
    el('p', { class: 'scope-note' }, [
      'Not production crypto. It runs entirely in your browser with no backend, the key lives for as long as the tab does and is never sent anywhere, and the whole point of it is to be broken. Do not use it to protect anything.',
    ]),
    details('The failure codes this lab can raise — and the one the program cannot', (out) => {
      out.append(
        el('p', {}, [
          'Every code below belongs to this page’s input validation. The white-box program has none. It cannot tell that it is being traced, it cannot refuse to run, and it raises nothing while its key is being extracted — a table network has no way to notice. The absence is the exhibit, not an omission.',
        ]),
        scroller(
          'Failure codes',
          table(
            'Failure codes, by who raises them',
            ['Code', 'Raised by'],
            [
              ...LAB_FAILURE_CODES.map((code): Cell[] => [
                { text: code, cls: 'mono' },
                { text: 'this page, validating what you typed or asked for' },
              ]),
              ...BGE_FAILURE_CODES.map((code): Cell[] => [
                { text: code, cls: 'mono' },
                {
                  text: 'the algebraic attack, refusing a round, a column or a table set it cannot work on',
                },
              ]),
              [
                { text: '(none)', cls: 'mono' },
                {
                  text: 'the white-box program itself, in every state, including while it is being broken',
                },
              ],
            ],
          ),
        ),
      );
    }),
  );
  node.append(body);
  return node;
}

// ── Act 1: the threat model ────────────────────────────────────────────────

function threatSection(): HTMLElement {
  const node = section(
    'act-threat',
    'Act 1',
    'The attacker owns the machine',
    'Ordinary cryptography assumes the attacker sees messages. White-box cryptography assumes they see everything.',
  );
  const body = panel();
  body.append(
    el('p', {}, [
      'Think about a video app on a phone someone has rooted, or a payment terminal in a shop, or a game that checks its own licence. The software has to decrypt something, so it has to have a key. And it is running on hardware the attacker owns.',
    ]),
    el('p', {}, [
      'So assume the worst honestly. The attacker has the program. They can read every byte of it, run it as often as they like on inputs they choose, stop it mid-instruction, and watch every value it puts in memory. The question white-box cryptography asks is whether the key can still not come out.',
    ]),
    el('p', {}, [
      'Chow, Eisen, Johnson and van Oorschot answered it in 2002 with a trick worth understanding before any of the detail: ',
      el('strong', {}, ['do not store the key at all.']),
      ' Turn the cipher into a network of lookup tables, and build each table with the key already mixed in. A table holding S(x ⊕ k) for all 256 values of x lets the program compute that step without the key being anywhere in it. Then scramble every value passing between tables with a secret random bijection, so no intermediate is a plain AES value either.',
    ]),
    el('p', {}, [
      'It is a genuinely good idea, and the rest of this page is about the two ways it fails. Jargon as it arrives: a ',
      el('em', {}, ['table network']),
      ' is a cipher rewritten as lookups; an ',
      el('em', {}, ['encoding']),
      ' is a secret bijection applied to a value so that what is stored is not what it means; a ',
      el('em', {}, ['trace']),
      ' is a recording of what a program read and wrote while it ran.',
    ]),
    details('Why lookup tables, and not just obfuscation', (out) => {
      out.append(
        el('p', {}, [
          'Obfuscation makes a program hard to read. It does not change what the program computes, so a debugger that stops at the right instruction still sees the key in a register. The table network is different in kind: the key is not a value the program ever holds, because the tables were built from it at compile time and shipped without it. That is a structural claim rather than a difficulty claim — which is why it can be attacked structurally, and is.',
        ]),
        el('p', {}, [
          'The cost is size. A Chow AES-128 is a few hundred kilobytes of tables instead of a 176-byte key schedule, and the exact figure is computed for you in Act 2.',
        ]),
      );
    }),
  );
  node.append(body);
  return node;
}

// ── Act 2: build the glass box ─────────────────────────────────────────────

const FIPS_KEY = '000102030405060708090a0b0c0d0e0f';

const diagram = createDiagram();
const buildOut = el('div', { id: 'build-out' });
const buildStatus = status('build-status');
const keyInput = el('input', {
  type: 'text',
  id: 'key-hex',
  class: 'mono',
  value: FIPS_KEY,
  spellcheck: 'false',
  autocomplete: 'off',
  'aria-describedby': 'key-hex-hint',
});
const keyError = el('p', {
  id: 'key-error',
  class: 'error',
  role: 'status',
  'aria-live': 'polite',
});
const seedInput = el('input', {
  type: 'text',
  id: 'seed',
  class: 'mono',
  value: '',
  spellcheck: 'false',
  autocomplete: 'off',
  'aria-describedby': 'seed-hint',
});

const PLACEMENT_OPTIONS = [
  {
    value: 'none',
    label: 'Nowhere — the program is plain AES',
    note: 'F and G are the identity. Feed it a plaintext, get a ciphertext.',
  },
  {
    value: 'compiled-in',
    label: 'Compiled into the program',
    note: 'The binary holds F and G and the tables that undo them.',
  },
  {
    value: 'remote-both',
    label: 'Both sides',
    note: 'A party outside the program applies F on input and removes G on output.',
    group: 'Applied remotely, outside the program',
  },
  {
    value: 'remote-input',
    label: 'Input side only',
    note: 'The program returns a real AES ciphertext.',
    group: 'Applied remotely, outside the program',
  },
  {
    value: 'remote-output',
    label: 'Output side only',
    note: 'The program takes a real AES plaintext.',
    group: 'Applied remotely, outside the program',
  },
] as const;

function randomKeyHex(): string {
  return [...crypto.getRandomValues(new Uint8Array(16))].map(byteHex).join('');
}

async function runBuild(): Promise<void> {
  keyError.textContent = '';
  keyInput.removeAttribute('aria-invalid');
  buildStatus.textContent = 'Building…';
  setBusy(true);
  try {
    const hadTraces = state.trace?.traces ?? 0;
    const hadAttack = state.dca !== null;
    const report = await ask<BuildReport & { id: number }>(
      {
        kind: 'build',
        keyHex: keyInput.value,
        placement: state.placement,
        seed: state.seed,
      },
      (phase, done, total) => {
        buildStatus.textContent = total > 1 ? `${phase} (${done} of ${total})` : `${phase}…`;
      },
    );
    state.build = report;
    // Only overwrite the note when this build actually retired something. A
    // second build in a row retires nothing, and blanking the note there would
    // make the first one's verdict disappear silently after all -- which is the
    // exact failure mode saying "retired" exists to prevent.
    if (hadTraces > 0 || hadAttack) {
      state.retired = {
        traces: hadTraces,
        attacked: hadAttack,
        reason: 'the program was rebuilt, so a different table network is in memory now',
      };
    }
    state.trace = null;
    state.dca = null;
    state.bge = null;
    state.runs.build += 1;
    buildStatus.textContent = `Program #${state.runs.build} built in ${report.buildMs} ms.`;
    renderBuild(report);
    renderTrace(null);
    renderDca(null);
    renderBge(null);
    renderFixture();
  } catch (error) {
    const err = error as Error & { code?: string };
    state.build = null;
    buildStatus.textContent = '';
    keyError.textContent = `${err.code ?? 'ERROR'} — ${err.message}`;
    if (err.code === 'KEY_HEX_MALFORMED' || err.code === 'KEY_LENGTH_INVALID') {
      keyInput.setAttribute('aria-invalid', 'true');
    }
    renderBuild(null);
  } finally {
    setBusy(false);
  }
}

function renderBuild(report: BuildReport | null): void {
  clear(buildOut);
  if (!report) {
    buildOut.append(el('p', { class: 'placeholder' }, ['No program is built. Fix the key and build one.']));
    return;
  }
  const v = report.verification;
  const ok = v.fipsVectorMatches && v.randomBlocksMatching === v.randomBlocks;
  buildOut.append(
    el('div', { class: 'verdict-row', id: 'build-verdict' }, [
      verdict(ok ? 'ok' : 'alarm', ok ? 'IT IS AES-128' : 'IT IS NOT AES-128', {
        'data-check': ok ? 'pass' : 'fail',
      }),
      el('span', { class: 'verdict-detail' }, [
        ok
          ? `The table network agrees with ${
              v.webCryptoAvailable ? 'WebCrypto' : 'this repository’s own reference'
            } on ${v.randomBlocksMatching} of ${v.randomBlocks} random blocks, and reproduces the FIPS 197 Appendix C.1 vector.`
          : `Only ${v.randomBlocksMatching} of ${v.randomBlocks} random blocks matched, and the FIPS vector ${
              v.fipsVectorMatches ? 'did' : 'did not'
            } reproduce. Something in the network is wrong.`,
      ]),
    ]),
    definitionList([
      ['FIPS 197 C.1 through the network', el('span', { class: 'mono' }, [group4(v.fipsCiphertextHex)])],
      ['External encodings', PLACEMENT_LABELS[report.placement]],
      [
        'Encodings drawn from',
        report.randomnessOrigin === 'system'
          ? 'crypto.getRandomValues — this instance is not reproducible'
          : 'a seed, expanded with AES-128-CTR — reproducible, and therefore NOT secret',
      ],
      ['Invertible matrices drawn', `${count(report.matrixDraws)} draws (rejection sampling over GL(n, 2))`],
      ['Tables in the program', count(report.tables)],
      ['Program size, as allocated here', bytesHuman(report.bytes)],
      [
        'Program size, 4-bit tables packed',
        `${bytesHuman(report.packedBytes)} — the accounting the literature uses, two nibble entries to a byte`,
      ],
      ['Bits one trace will record', count(report.traceBits)],
    ]),
    scroller(
      'Table inventory',
      table(
        'Every table in the program, counted from the arrays that were allocated',
        ['Type', 'Tables', 'Bytes each', 'Bytes', 'What it does'],
        report.groups.map((g): Cell[] => [
          { text: g.label, cls: 'mono' },
          { text: count(g.count) },
          { text: count(g.entryBytes) },
          { text: bytesHuman(g.bytes) },
          { text: g.note },
        ]),
      ),
    ),
  );
  if (report.encoderInProgram) {
    buildOut.append(
      el('p', { class: 'aside-note', id: 'encoder-note' }, [
        'This program contains the encoder as well as the tables that strip it. Composed, they are the identity — which is why its exported behaviour is plain AES, and why Act 4 reads exactly the same first-round values it reads with no external encoding at all. Act 5 measures that rather than asserting it.',
      ]),
    );
  }
  diagram.update(report.placement);
}

function buildSection(): HTMLElement {
  const node = section(
    'act-build',
    'Act 2',
    'Build the glass box',
    'Choose a key. The page compiles it into a Chow table network in your browser, then checks that network against an independent AES before telling you anything else.',
  );
  const controls = panel('controls');
  controls.append(
    el('div', { class: 'control-row' }, [
      field('key-hex', 'AES-128 key (32 hex digits)', keyInput, 'The default is the FIPS 197 Appendix C.1 key.'),
      button('generate-key', 'Generate a key', 'plain', () => {
        keyInput.value = randomKeyHex();
        void runBuild();
      }),
    ]),
    keyError,
    field(
      'seed',
      'Encoding seed (optional)',
      seedInput,
      'Leave it empty for crypto.getRandomValues. A seed reproduces the exact instance — encodings, mixing bijections and all — which makes it reproducible and therefore not secret.',
    ),
    radioGroup('placement', 'Where the external encodings live', PLACEMENT_OPTIONS, state.placement, (value) => {
      // Re-selecting what is already selected must not retire a fresh verdict.
      // Browsers do not fire `change` for a click on an already-checked radio,
      // but a programmatic `.check()` or a future control might, and a rebuild
      // would silently throw away the traces and the attack on screen.
      if (value === state.placement && state.build) return;
      state.placement = value as EncodingPlacement;
      void runBuild();
    }),
    el('div', { class: 'control-row' }, [button('build', 'Build the program', 'primary', () => void runBuild())]),
    buildStatus,
  );
  const out = panel();
  out.append(el('h3', {}, ['What was built']), buildOut);
  const dia = panel();
  dia.append(
    el('h3', {}, ['One column of round 1, as tables']),
    diagram.node,
    details('The five table types, and why the mixing bijections are not optional', (body) => {
      body.append(
        el('p', {}, [
          'Chow’s round is reordered so ShiftRows happens first, which lets a single 256-entry table hold "add this round key byte, then apply the S-box". That table is a ',
          el('strong', {}, ['T-box']),
          '. MixColumns is folded into the same lookup by composing it with Tyᵢ, which spreads one input byte across all four bytes of a column; summing the four results reconstructs the column. Summing is done by ',
          el('strong', {}, ['nibble XOR tables']),
          ', because a table that XORs two whole bytes would need 65,536 entries and one that XORs two nibbles needs 256.',
        ]),
        el('p', {}, [
          'On top of that sit two kinds of secret linear map, and the reason they matter is worth stating plainly: without them, a T-box output would be a nibble-encoded S-box output, and an attacker could peel the encoding off one byte at a time. The 32×32 mixing bijection MB makes each Type II output a linear mix of the whole column’s worth of bits; the 8×8 ones make each byte crossing a round boundary a linear mix of its own bits. Both are drawn uniformly from GL(n, 2) by rejection sampling, at full size, in this page.',
        ]),
        el('p', {}, [
          'The count works out as 9 rounds × 4 columns × (4 Type II + 24 Type IV + 4 Type III + 24 Type IV), plus 16 Type V tables for round 10, which has no MixColumns. The inventory above is read off the arrays that were actually allocated, so the number you see is the number that exists.',
        ]),
      );
    }),
  );
  node.append(controls, out, dia);
  return node;
}

// ── Act 3: trace it ───────────────────────────────────────────────────────

const traceOut = el('div', { id: 'trace-out' });
const traceStatus = status('trace-status');
const traceFigure = figure('trace-heatmap', 'Trace heatmap, scrollable', 'No traces recorded yet.');
const traceRange = el('input', {
  type: 'range',
  id: 'traces-range',
  min: String(MIN_TRACES),
  max: String(MAX_TRACES),
  step: '8',
  value: String(state.traces),
});
const traceNumber = el('input', {
  type: 'number',
  id: 'traces',
  class: 'mono',
  min: String(MIN_TRACES),
  max: String(MAX_TRACES),
  value: String(state.traces),
  'aria-describedby': 'traces-hint',
});
const traceError = el('p', {
  id: 'trace-error',
  class: 'error',
  role: 'status',
  'aria-live': 'polite',
});

function syncTraceInputs(from: 'range' | 'number'): void {
  const raw = Number(from === 'range' ? traceRange.value : traceNumber.value);
  state.traces = Number.isFinite(raw) ? Math.round(raw) : DEFAULT_TRACES;
  if (from === 'number') {
    traceRange.value = String(Math.max(MIN_TRACES, Math.min(MAX_TRACES, state.traces)));
  } else {
    traceNumber.value = String(state.traces);
  }
}
traceRange.addEventListener('input', () => syncTraceInputs('range'));
traceNumber.addEventListener('input', () => syncTraceInputs('number'));

async function runTrace(): Promise<void> {
  traceError.textContent = '';
  traceNumber.removeAttribute('aria-invalid');
  if (!state.build) {
    traceError.textContent = 'NO_PROGRAM_BUILT — build the program first: the trace is of its table lookups.';
    return;
  }
  setBusy(true);
  traceStatus.textContent = 'Tracing…';
  try {
    const report = await ask<TraceReport & { id: number }>(
      { kind: 'trace', traces: state.traces },
      (phase, done, total) => {
        traceStatus.textContent = `${phase}: ${count(done)} of ${count(total)}`;
      },
    );
    state.trace = report;
    state.dca = null;
    // The note has been made good on: these traces describe the program that is
    // in memory now.
    state.retired = null;
    state.runs.trace += 1;
    traceStatus.textContent = `Run #${state.runs.trace}: recorded ${count(report.traces)} traces in ${report.elapsedMs} ms.`;
    renderTrace(report);
    renderDca(null);
    await refreshHeatmap();
  } catch (error) {
    const err = error as Error & { code?: string };
    state.trace = null;
    traceStatus.textContent = '';
    traceError.textContent = `${err.code ?? 'ERROR'} — ${err.message}`;
    if (err.code === 'TRACE_COUNT_OUT_OF_RANGE' || err.code === 'TRACE_BUDGET_EXCEEDED') {
      traceNumber.setAttribute('aria-invalid', 'true');
    }
    renderTrace(null);
  } finally {
    setBusy(false);
  }
}

function renderTrace(report: TraceReport | null): void {
  clear(traceOut);
  if (!report) {
    // A blank panel looks like a page that has never been used. Saying WHAT was
    // retired, and why, is the difference between an empty state and a stale
    // verdict quietly disappearing.
    if (state.retired && state.retired.traces > 0) {
      traceOut.append(
        el('div', { class: 'verdict-row', id: 'trace-retired', 'data-retired': 'trace' }, [
          verdict('warn', 'RETIRED'),
          el('span', { class: 'verdict-detail' }, [
            `The ${count(state.retired.traces)} traces that were here described a different program: ${state.retired.reason}. Record new ones.`,
          ]),
        ]),
      );
    } else {
      traceOut.append(el('p', { class: 'placeholder' }, ['No traces recorded. Press "Trace it".']));
    }
    traceFigure.describe('No traces recorded yet.');
    return;
  }
  traceOut.append(
    definitionList([
      ['Traced encryptions', count(report.traces)],
      ['Samples per trace', `${count(report.bitsPerTrace)} bits, one per bit of every table lookup output`],
      [
        'Buffer size',
        `${bytesHuman(report.bufferBytes)}, predicted as ${bytesHuman(
          report.predictedBufferBytes,
        )} before anything was allocated`,
      ],
      ['Samples that took both values', percent(report.varyingSamples)],
      ['Time to record', `${report.elapsedMs} ms`],
      [
        'Windows the attack can choose',
        Object.entries(report.windows)
          .map(([name, w]) => `${name}: ${count(w.bits)} samples from ${count(w.startBit)}`)
          .join(' · '),
      ],
    ]),
  );
  if (state.build) {
    traceOut.append(
      scroller(
        'Trace segment map',
        table(
          'Where each part of the program lands in a trace',
          ['Segment', 'First sample', 'Samples'],
          state.build.segments.map((s): Cell[] => [
            { text: s.label, cls: 'mono' },
            { text: count(s.startBit) },
            { text: count(s.bits) },
          ]),
        ),
      ),
    );
  }
}

function traceSection(): HTMLElement {
  const node = section(
    'act-trace',
    'Act 3',
    'Make the program tell on itself',
    'Run the program on random inputs and record the output of every table lookup it performs, in order. That recording is the only thing the attack in Act 4 gets.',
  );
  const controls = panel('controls');
  controls.append(
    el('div', { class: 'control-row' }, [
      field('traces-range', 'Traces to record', traceRange),
      field(
        'traces',
        'or type an exact number',
        traceNumber,
        `Between ${MIN_TRACES} and ${count(MAX_TRACES)}, which covers the 2,000 traces Bos et al. report using. There is a second cap, on BYTES rather than traces: a buffer is one bit per sample per trace, and how many samples a trace has depends on how big the program is. This lab computes the size before allocating anything and refuses over ${bytesHuman(TRACE_BUDGET_BYTES)} \u2014 which the compiled-in placement reaches first, because its program is twice the size.`,
      ),
      button('trace', 'Trace it', 'primary', () => void runTrace()),
    ]),
    traceError,
    traceStatus,
  );
  const out = panel();
  out.append(el('h3', {}, ['The recording']), traceOut);
  const fig = panel();
  fig.append(
    el('h3', {}, ['The trace, bit by bit']),
    el('p', {}, [
      'One row per traced encryption, one column per recorded bit, light for a 1 and dark for a 0. The repeating block structure across the row is the round’s four columns — and noticing that structure is how Bos et al. narrow a captured trace to a single round before running any statistics.',
    ]),
    traceFigure.wrap,
  );
  node.append(controls, out, fig);
  return node;
}

// ── Act 4: differential computation analysis ───────────────────────────────

const dcaStatus = status('dca-status');
const dcaError = el('p', {
  id: 'dca-error',
  class: 'error',
  role: 'status',
  'aria-live': 'polite',
});
const dcaOut = el('div', { id: 'dca-out' });
const dcaInspect = el('div', { id: 'dca-inspect' });
const peaksFigure = figure('peaks-plot', 'Peak per guess, scrollable', 'No attack has run yet.');
const focusFigure = figure('focus-heatmap', null, 'No attack has run yet.');
const curvesFigure = figure('curves-plot', 'Difference-of-means curves, scrollable', 'No attack has run yet.');
const byteStrip = el('div', {
  id: 'byte-strip',
  class: 'byte-strip',
  role: 'list',
  'aria-label': 'Recovered key bytes',
});

const targetChecks = el('div', { class: 'check-row', id: 'target-checks' });
const bitSelect = select(
  'bit-select',
  [
    { value: 'all', label: 'all eight bits' },
    ...[0, 1, 2, 3, 4, 5, 6, 7].map((b) => ({
      value: String(b),
      label: `bit ${b} only`,
    })),
  ],
  'all',
  (value) => {
    state.bitChoice = value === 'all' ? 'all' : Number(value);
  },
);
const byteSelect = select(
  'byte-select',
  [...Array(16).keys()].map((i) => ({ value: String(i), label: `byte ${i}` })),
  '0',
  (value) => {
    state.inspectByte = Number(value);
    void refreshInspector();
  },
);
const guessSelect = select(
  'guess-select',
  [
    { value: 'recovered', label: 'the value the attack chose' },
    { value: 'wrong', label: 'a deliberately wrong value' },
  ],
  'recovered',
  (value) => {
    state.inspectGuess = value as 'recovered' | 'wrong';
    void refreshInspector();
  },
);

function renderTargetChecks(): void {
  clear(targetChecks);
  if (state.surface === 'input') {
    targetChecks.append(
      checkbox('target-sbox', 'SubBytes output, S(p ⊕ k)', state.inputTargets.includes('sbox-output'), (on) => {
        state.inputTargets = on
          ? [...new Set<DcaTarget>([...state.inputTargets, 'sbox-output'])]
          : state.inputTargets.filter((t) => t !== 'sbox-output');
      }),
      checkbox(
        'target-inverse',
        'Multiplicative inverse inside SubBytes, (p ⊕ k)⁻¹',
        state.inputTargets.includes('inverse'),
        (on) => {
          state.inputTargets = on
            ? [...new Set<DcaTarget>([...state.inputTargets, 'inverse'])]
            : state.inputTargets.filter((t) => t !== 'inverse');
        },
      ),
      el('p', { class: 'hint' }, [
        'Tick both to combine them: the score of a candidate becomes the largest peak over either target, which is what a real attacker does. Bos et al. report recovering bytes from the inverse target that the SubBytes-output target left unrecovered, and the whole key when the two are combined.',
      ]),
    );
  } else {
    targetChecks.append(
      el('p', { class: 'hint', id: 'output-target-note' }, [
        'The output side has exactly one target: S⁻¹(c ⊕ k¹⁰), the round-10 state before the final SubBytes. There is no second one to offer. Predicting c ⊕ k¹⁰ itself would be useless, because XOR with the guess is linear — every candidate would produce the same partition up to a complement.',
      ]),
    );
  }
}

function wrongGuessFor(chosen: number): number {
  // A fixed offset, so the "wrong" comparison is reproducible rather than a
  // fresh random each time the reader looks at it.
  return (chosen ^ 0x5a) & 0xff;
}

async function refreshHeatmap(): Promise<void> {
  if (!state.trace) {
    traceFigure.describe('No traces recorded yet.');
    return;
  }
  // Act 3 shows the WHOLE recording, with the round boundaries marked from the
  // program's own segment map; Act 4's strip shows the window the attack chose.
  const whole = await ask<HeatmapReport & { id: number }>({
    kind: 'heatmap',
    sortBy: null,
    window: 'whole-program',
    focusSample: null,
    maxRows: 200,
    focusHalfWidth: 0,
  });
  traceFigure.describe(
    drawTraceHeatmap(
      traceFigure.canvas,
      whole,
      (state.build?.segments ?? [])
        .filter((s) => s.id.startsWith('round:'))
        .map((s) => ({ label: s.label, startBit: s.startBit })),
    ),
  );

  const dca = state.dca;
  const sortBy =
    dca && dca.bytes.length > 0
      ? {
          byteIndex: state.inspectByte,
          guess:
            state.inspectGuess === 'recovered'
              ? dca.bytes[state.inspectByte].guess
              : wrongGuessFor(dca.bytes[state.inspectByte].guess),
          target: dca.bytes[state.inspectByte].peakTarget,
          bit: dca.bytes[state.inspectByte].peakBit >= 0 ? dca.bytes[state.inspectByte].peakBit : 0,
        }
      : null;
  const focusSample = dca ? dca.bytes[state.inspectByte].peakSample : null;
  if (focusSample === null) {
    focusFigure.describe(
      'No sample is in focus yet: run the attack, and this strip will centre on the sample it peaked at.',
    );
    return;
  }
  const strip = await ask<HeatmapReport & { id: number }>({
    kind: 'heatmap',
    sortBy,
    window: dca ? dca.window : 'first-round',
    focusSample,
    maxRows: 96,
    focusHalfWidth: 8,
  });
  focusFigure.describe(drawFocusHeatmap(focusFigure.canvas, strip, focusSample));
}

async function refreshInspector(): Promise<void> {
  const dca = state.dca;
  if (!dca) return;
  const byteReport = dca.bytes[state.inspectByte];
  peaksFigure.describe(drawPeaksPerGuess(peaksFigure.canvas, byteReport, true));
  await refreshHeatmap();
}

async function runDcaAttack(): Promise<void> {
  dcaError.textContent = '';
  if (!state.trace) {
    dcaError.textContent = 'NO_TRACES_RECORDED — record some traces first: DCA is a statistical attack on them.';
    return;
  }
  const targets = targetsSelected();
  if (targets.length === 0) {
    dcaError.textContent =
      'NO_HYPOTHESIS_SELECTED — pick at least one target and one prediction bit: with none there is nothing to correlate.';
    return;
  }
  setBusy(true);
  dcaStatus.textContent = 'Scoring hypotheses…';
  try {
    const report = await ask<DcaReport & { id: number }>(
      {
        kind: 'dca',
        surface: state.surface,
        targets,
        bits: bitsSelected(),
        curveByte: state.inspectByte,
      },
      (phase, done, total) => {
        dcaStatus.textContent = `${phase}: key byte ${done} of ${total}`;
      },
    );
    state.dca = report;
    // Open the inspector on the byte the attack is most confident about, so the
    // arrival view of this panel shows the mechanism working. Every other byte
    // is one selection away, including the ones it got wrong.
    let best = 0;
    for (let i = 1; i < 16; i++) if (report.bytes[i].margin > report.bytes[best].margin) best = i;
    state.inspectByte = best;
    byteSelect.value = String(best);
    state.runs.dca += 1;
    dcaStatus.textContent = `Attack #${state.runs.dca}: scored ${count(
      256 * 16 * targets.length * bitsSelected().length,
    )} hypothesis evaluations in ${report.elapsedMs} ms.`;
    recordLogRow(report);
    renderDca(report);
    await refreshInspector();
    curvesFigure.describe(drawCurves(curvesFigure.canvas, report));
    renderLog();
    renderFixture();
  } catch (error) {
    const err = error as Error & { code?: string };
    state.dca = null;
    dcaStatus.textContent = '';
    dcaError.textContent = `${err.code ?? 'ERROR'} — ${err.message}`;
    renderDca(null);
  } finally {
    setBusy(false);
  }
}

function headlineFor(report: DcaReport): { tone: VerdictTone; text: string } {
  const what = report.recovers === 'key' ? 'KEY' : 'LAST ROUND KEY';
  if (report.complete)
    return {
      tone: 'alarm',
      text: `${what} RECOVERED — ${report.correctCount} OF 16 BYTES`,
    };
  if (report.correctCount >= 4)
    return {
      tone: 'warn',
      text: `${what} PARTLY RECOVERED — ${report.correctCount} OF 16 BYTES`,
    };
  return {
    tone: 'ok',
    text: `NO RECOVERY — ${report.correctCount} OF 16 BYTES`,
  };
}

function renderDca(report: DcaReport | null): void {
  clear(dcaOut);
  clear(byteStrip);
  clear(dcaInspect);
  if (!report) {
    if (state.retired?.attacked) {
      dcaOut.append(
        el('div', { class: 'verdict-row', id: 'dca-retired', 'data-retired': 'dca' }, [
          verdict('warn', 'RETIRED'),
          el('span', { class: 'verdict-detail' }, [
            `The recovery that was here was of a different key, from a different program: ${state.retired.reason}. Trace again and re-run the attack.`,
          ]),
        ]),
      );
    } else {
      dcaOut.append(el('p', { class: 'placeholder' }, ['No attack has run. Press "Run the attack".']));
    }
    byteStrip.append(el('span', { class: 'placeholder', role: 'listitem' }, ['—']));
    peaksFigure.describe('No attack has run yet.');
    curvesFigure.describe('No attack has run yet.');
    return;
  }
  const head = headlineFor(report);
  const confident = report.bytes.filter((b) => b.margin >= CONFIDENCE_MARGIN);
  const confidentWrong = confident.filter((b) => !b.correct);

  dcaOut.append(
    el(
      'div',
      {
        class: 'verdict-row',
        id: 'dca-verdict',
        'data-dca-recovered': String(report.correctCount),
        'data-dca-complete': report.complete ? 'yes' : 'no',
      },
      [
        verdict(head.tone, head.text),
        el('span', { class: 'verdict-detail' }, [
          `${count(report.traces)} traces, ${count(report.sampleCount)} samples (${report.windowLabel}), ` +
            `${report.targets.map((t) => TARGET_LABELS[t]).join(' and ')}, ` +
            `${report.bits.length === 8 ? 'all eight prediction bits' : `bit ${report.bits[0]}`}.`,
        ]),
      ],
    ),
    definitionList([
      ['What the attack committed to', el('span', { class: 'mono' }, [group4(report.recoveredHex)])],
      ['The truth, consulted only afterwards', el('span', { class: 'mono' }, [group4(report.truthHex)])],
      [
        'Bytes correct',
        `${report.correctCount} of 16 (a blind guesser would expect ${report.chanceCorrect.toFixed(2)})`,
      ],
      [
        'Bytes the attack was confident about',
        `${confident.length} at a margin of ${CONFIDENCE_MARGIN} or better, of which ${confidentWrong.length} ${
          confidentWrong.length === 1 ? 'was' : 'were'
        } wrong`,
      ],
      ...(report.derivedKeyHex !== null
        ? ([
            ['The key the inverse schedule gives', el('span', { class: 'mono' }, [group4(report.derivedKeyHex)])],
            [
              'and how much of it is right',
              `${report.derivedKeyCorrectCount} of 16 — inverting the AES-128 schedule needs ALL sixteen bytes of k¹⁰, so one wrong byte corrupts everything downstream of it`,
            ],
          ] as (readonly [string, string | Node])[])
        : []),
      ['Time to score', `${report.elapsedMs} ms`],
    ]),
  );
  if (!report.hypothesisValid) {
    dcaOut.append(
      el('p', { class: 'aside-note', id: 'no-hypothesis-note' }, [
        'In this placement the attacker cannot form a hypothesis about this side at all: the value they feed the program, or the value it returns, is not an AES plaintext or ciphertext, and they do not hold the encoding that relates the two. The attack still runs, and what it reports is what chance reports.',
      ]),
    );
  }

  for (const b of report.bytes) {
    const tone: VerdictTone = b.correct ? 'alarm' : b.margin >= CONFIDENCE_MARGIN ? 'warn' : 'ok';
    byteStrip.append(
      el(
        'div',
        {
          class: `byte-cell tone-${tone}`,
          role: 'listitem',
          'data-byte': String(b.index),
        },
        [
          el('span', { class: 'byte-index' }, [`k${b.index}`]),
          el('span', { class: 'byte-value mono' }, [byteHex(b.guess)]),
          el('span', { class: 'byte-glyph', 'aria-hidden': 'true' }, [b.correct ? '✓' : '✕']),
          el('span', { class: 'byte-state' }, [b.correct ? 'found' : 'missed']),
          el('span', { class: 'byte-margin mono' }, [`${Math.round(b.margin * 100)}%`]),
        ],
      ),
    );
  }

  dcaInspect.append(
    el('div', { class: 'control-row' }, [
      field('byte-select', 'Inspect key byte', byteSelect),
      field('guess-select', 'Split the traces by', guessSelect),
    ]),
    el('div', { class: 'two-up' }, [
      el('div', {}, [el('h4', {}, ['Peak per candidate']), peaksFigure.wrap]),
      el('div', {}, [
        el('h4', {}, ['The same traces, split by the predicted bit']),
        el('p', {}, [
          'The rows above the gap are the traces whose predicted bit is 0 and the rows below are the ones where it is 1. Beneath them, the bar pairs are the fraction of 1 bits in each half at each sample \u2014 the difference of means itself, not a picture of it. Under the value the attack chose, one pair pulls apart. Under a deliberately wrong value every pair stays level. That is the whole attack.',
        ]),
        focusFigure.wrap,
      ]),
    ]),
    details('Every candidate’s curve across the window', (body) => {
      body.append(
        el('p', {}, [
          'One faint curve per wrong candidate, the winner drawn over them. It shows WHERE the leak is: the winning curve sits in the same noise as the others almost everywhere and spikes at the handful of samples where the encoded nibble it correlates with is being written.',
        ]),
        curvesFigure.wrap,
      );
    }),
    details('Per-byte detail: margin, sample, target and bit', (body) => {
      body.append(
        scroller(
          'Per-byte attack detail',
          table(
            'What the attack found for each key byte',
            ['Byte', 'Chose', 'Peak', 'Runner-up', 'Margin', 'Sample', 'Target', 'Bit', 'Correct'],
            report.bytes.map((b): Cell[] => [
              { text: `k${b.index}` },
              { text: `0x${byteHex(b.guess)}`, cls: 'mono' },
              { text: b.peak.toFixed(4), cls: 'mono' },
              {
                text: `0x${byteHex(b.runnerUpGuess)} at ${b.runnerUp.toFixed(4)}`,
                cls: 'mono',
              },
              { text: `${Math.round(b.margin * 100)}%`, cls: 'mono' },
              { text: count(b.peakSample), cls: 'mono' },
              { text: b.peakTarget, cls: 'mono' },
              { text: b.peakBit >= 0 ? String(b.peakBit) : '—', cls: 'mono' },
              {
                node: verdict(b.correct ? 'alarm' : 'ok', b.correct ? 'yes' : 'no'),
              },
            ]),
          ),
        ),
      );
    }),
  );
}

function dcaSection(): HTMLElement {
  const node = section(
    'act-dca',
    'Act 4',
    'Take the key out of the trace',
    'For each key byte and each of 256 candidate values, predict one bit of a first-round intermediate, split the traces by that prediction, and measure the difference in the averages. The candidate whose split separates the traces best is the byte.',
  );
  const controls = panel('controls');
  controls.append(
    radioGroup(
      'surface',
      'Which side to attack',
      [
        {
          value: 'input',
          label: 'The input side, round 1',
          note: 'Predicts from the value fed to the program.',
        },
        {
          value: 'output',
          label: 'The output side, rounds 9 and 10',
          note: 'Predicts from the value the program returns.',
        },
      ],
      state.surface,
      (value) => {
        state.surface = value as AttackSurface;
        renderTargetChecks();
      },
    ),
    el('fieldset', { class: 'radios' }, [el('legend', {}, ['What to predict']), targetChecks]),
    el('div', { class: 'control-row' }, [
      field(
        'bit-select',
        'Prediction bit',
        bitSelect,
        'One bit of the predicted intermediate is all the distinguisher needs. Which bit leaks depends on the instance, so scoring all eight and keeping the best is both cheaper than guessing and what an attacker would do.',
      ),
      button('run-dca', 'Run the attack', 'primary', () => void runDcaAttack()),
    ]),
    dcaError,
    dcaStatus,
  );
  const out = panel();
  out.append(
    el('h3', {}, ['What came out']),
    dcaOut,
    el('h4', {}, ['The sixteen key bytes']),
    el('p', { class: 'hint' }, [
      'Each cell shows what the attack chose, whether it was right, and the margin between its best and second-best candidate. The margin is computed without the key, so it is the confidence an attacker would actually have.',
    ]),
    el('p', { class: 'hint' }, [
      'Colour tracks what it MEANS, not whether a computation succeeded: a byte the attack found is a security failure and reads as alarm, a byte it missed reads as safe. Every cell says so in words and in a glyph as well, so the colour is never carrying the meaning on its own.',
    ]),
    byteStrip,
  );
  const inspect = panel();
  inspect.append(el('h3', {}, ['Why it works']), dcaInspect);
  node.append(controls, out, inspect);
  return node;
}

// ── Act 5: where the external encodings live ───────────────────────────────

const logHost = el('div', { id: 'placement-log' });
const fixtureHost = el('div', { id: 'neg-fixture' });
const sweepStatus = status('sweep-status');

function recordLogRow(report: DcaReport): void {
  if (!state.build) return;
  const confident = report.bytes.filter((b) => b.margin >= CONFIDENCE_MARGIN);
  const row = {
    placement: state.build.placement,
    surface: report.surface,
    traces: report.traces,
    targets: report.targets,
    correctCount: report.correctCount,
    complete: report.complete,
    confident: confident.length,
    confidentWrong: confident.filter((b) => !b.correct).length,
    tables: state.build.tables,
    bytes: state.build.bytes,
    traceBits: state.build.traceBits,
    recovers: report.recovers,
    hypothesisValid: report.hypothesisValid,
  };
  const existing = state.log.findIndex((r) => r.placement === row.placement && r.surface === row.surface);
  if (existing >= 0) state.log[existing] = row;
  else state.log.push(row);
}

function renderLog(): void {
  clear(logHost);
  if (state.log.length === 0) {
    logHost.append(
      el('p', { class: 'placeholder' }, [
        'Nothing measured yet. Run Act 4 once, then change where the encodings live in Act 2 and run it again — each state gets a row here, filled in from what actually happened.',
      ]),
    );
    return;
  }
  logHost.append(
    scroller(
      'Measured results by encoding placement',
      table(
        'Every placement and side you have actually run',
        [
          'Where the encodings live',
          'Side attacked',
          'Traces',
          'Bytes recovered',
          'Confident',
          'Tables',
          'Program',
          'Trace bits',
        ],
        state.log.map((r): Cell[] => [
          { text: PLACEMENT_LABELS[r.placement] },
          {
            text: r.surface === 'input' ? 'input, round 1' : 'output, rounds 9–10',
          },
          { text: count(r.traces), cls: 'mono' },
          {
            node: el('span', { class: 'cell-stack' }, [
              verdict(r.complete ? 'alarm' : r.correctCount >= 4 ? 'warn' : 'ok', `${r.correctCount} of 16`, {
                'data-log-recovered': String(r.correctCount),
              }),
              el('span', { class: 'cell-sub' }, [r.recovers === 'key' ? 'of the key' : 'of the last round key']),
            ]),
          },
          {
            text: `${r.confident}${r.confidentWrong > 0 ? ` (${r.confidentWrong} wrong)` : ''}`,
            cls: 'mono',
          },
          { text: count(r.tables), cls: 'mono' },
          { text: bytesHuman(r.bytes), cls: 'mono' },
          { text: count(r.traceBits), cls: 'mono' },
        ]),
      ),
    ),
  );
  const plain = state.log.find((r) => r.placement === 'none' && r.surface === 'input');
  const compiled = state.log.find((r) => r.placement === 'compiled-in' && r.surface === 'input');
  if (plain && compiled) {
    const same = plain.correctCount === compiled.correctCount;
    logHost.append(
      el(
        'div',
        { class: 'verdict-row', id: 'compiled-in-comparison', 'data-comparison': same ? 'identical' : 'different' },
        [
          verdict(same ? 'alarm' : 'warn', same ? 'THE ENCODING CHANGED NOTHING' : 'THE TWO RUNS DIFFER'),
          el('span', { class: 'verdict-detail' }, [
            `Compiling the external encodings in grew the program from ${count(plain.tables)} tables (${bytesHuman(
              plain.bytes,
            )}) to ${count(compiled.tables)} tables (${bytesHuman(compiled.bytes)}) and a trace from ${count(
              plain.traceBits,
            )} bits to ${count(compiled.traceBits)}. The attack recovered ${plain.correctCount} bytes before and ${
              compiled.correctCount
            } after.`,
          ]),
        ],
      ),
    );
  }
}

async function runSweep(): Promise<void> {
  const savedKey = keyInput.value;
  const savedSeed = state.seed;
  setBusy(true);
  const plan: { placement: EncodingPlacement; surface: AttackSurface }[] = [
    { placement: 'none', surface: 'input' },
    { placement: 'compiled-in', surface: 'input' },
    { placement: 'remote-output', surface: 'input' },
    { placement: 'remote-both', surface: 'input' },
    { placement: 'remote-both', surface: 'output' },
    { placement: 'remote-input', surface: 'input' },
    { placement: 'remote-input', surface: 'output' },
  ];
  // One seed across the sweep, so the AES core is identical in every state and
  // the comparison is of the placements rather than of seven random instances.
  const sweepSeed = state.seed.length > 0 ? state.seed : `sweep-${Date.now()}`;
  try {
    let built: EncodingPlacement | null = null;
    for (let step = 0; step < plan.length; step++) {
      const { placement, surface } = plan[step];
      sweepStatus.textContent = `Measuring ${PLACEMENT_LABELS[placement]}, ${surface} side (${step + 1} of ${plan.length})…`;
      if (built !== placement) {
        state.build = await ask<BuildReport & { id: number }>({
          kind: 'build',
          keyHex: savedKey,
          placement,
          seed: sweepSeed,
        });
        built = placement;
        state.trace = await ask<TraceReport & { id: number }>({
          kind: 'trace',
          traces: state.traces,
        });
      }
      const targets: DcaTarget[] = surface === 'input' ? ['sbox-output', 'inverse'] : ['last-round'];
      const report = await ask<DcaReport & { id: number }>({
        kind: 'dca',
        surface,
        targets,
        bits: [0, 1, 2, 3, 4, 5, 6, 7],
        curveByte: null,
      });
      state.dca = report;
      recordLogRow(report);
      renderLog();
    }
    sweepStatus.textContent = `Measured all ${plan.length} combinations at ${count(state.traces)} traces, seed "${sweepSeed}".`;
    // Leave the page on the state that carries the negative claim.
    state.placement = 'remote-both';
    for (const input of document.querySelectorAll<HTMLInputElement>('input[name="placement"]')) {
      input.checked = input.value === 'remote-both';
    }
    state.build = await ask<BuildReport & { id: number }>({
      kind: 'build',
      keyHex: savedKey,
      placement: 'remote-both',
      seed: sweepSeed,
    });
    state.trace = await ask<TraceReport & { id: number }>({
      kind: 'trace',
      traces: state.traces,
    });
    state.dca = await ask<DcaReport & { id: number }>({
      kind: 'dca',
      surface: 'input',
      targets: ['sbox-output', 'inverse'],
      bits: [0, 1, 2, 3, 4, 5, 6, 7],
      curveByte: state.inspectByte,
    });
    renderBuild(state.build);
    renderTrace(state.trace);
    renderDca(state.dca);
    await refreshInspector();
    curvesFigure.describe(drawCurves(curvesFigure.canvas, state.dca));
    await renderFixture();
  } catch (error) {
    sweepStatus.textContent = `The sweep stopped: ${(error as Error).message}`;
  } finally {
    state.seed = savedSeed;
    setBusy(false);
  }
}

/**
 * The NEG-1 evidence fixture.
 *
 * Reachable only in the state the negative claim is about: the external
 * encodings held outside the program on both sides, traced, and attacked. In
 * that state every check this page performs reports that the defence held --
 * and the same tables give their encodings up to an algebraic attack that used
 * no traces at all, which is run here, in that state, to make the claim a result.
 */
async function renderFixture(): Promise<void> {
  clear(fixtureHost);
  const build = state.build;
  const dca = state.dca;
  if (!build || !dca || build.placement !== 'remote-both') {
    fixtureHost.append(
      el('p', { class: 'placeholder' }, [
        'The state this lab makes its negative claim about is "remote, both sides", traced and attacked. Select it in Act 2, trace, and run the attack — or press the sweep button above, which ends there.',
      ]),
    );
    return;
  }
  if (dca.correctCount > 2) {
    fixtureHost.append(
      el('p', { class: 'aside-note' }, [
        `In this run the attack recovered ${dca.correctCount} of 16 bytes with the encodings held remotely on both sides. That is not the state the negative claim describes, and it would mean a leak across the module boundary rather than luck. The claim is not shown for a state it is not about.`,
      ]),
    );
    return;
  }

  let bge: BgeReport | null = state.bge;
  if (!bge) {
    try {
      bge = await ask<BgeReport & { id: number }>({
        kind: 'bge',
        round: state.bgeRound,
        column: state.bgeColumn,
      });
      state.bge = bge;
      renderBge(bge);
    } catch {
      bge = null;
    }
  }

  const checks: { label: string; pass: boolean; detail: string }[] = [
    {
      label: 'The program is a correct AES-128',
      pass:
        build.verification.fipsVectorMatches &&
        build.verification.randomBlocksMatching === build.verification.randomBlocks,
      detail: `${build.verification.randomBlocksMatching} of ${build.verification.randomBlocks} random blocks agree with ${
        build.verification.webCryptoAvailable ? 'WebCrypto' : 'the reference'
      }, and the FIPS 197 vector reproduces.`,
    },
    {
      label: 'Differential computation analysis recovered nothing',
      pass: dca.correctCount <= 2,
      detail: `${dca.correctCount} of 16 bytes, against ${dca.chanceCorrect.toFixed(2)} expected from blind guessing, over ${count(
        dca.traces,
      )} traces and ${count(dca.sampleCount)} samples.`,
    },
    {
      label: 'The attacker has no hypothesis to form on this side',
      pass: !dca.hypothesisValid,
      detail:
        'The value fed to the program is F(P) for an F the program does not contain, so no candidate key byte predicts anything about the trace.',
    },
    {
      label: 'The program raised no failure code',
      pass: true,
      detail: 'There is none to raise. A table network cannot tell that it is being traced and has no code for it.',
    },
  ];
  const allGreen = checks.every((c) => c.pass);

  fixtureHost.append(
    el('div', { class: 'verdict-row' }, [
      verdict(allGreen ? 'warn' : 'ok', 'DCA DEFEATED — AND THE ENCODINGS RECOVERED ANYWAY', {
        'data-fixture-verdict': allGreen ? 'reached' : 'incomplete',
      }),
    ]),
    el(
      'ul',
      {
        class: 'plain-list check-list',
        role: 'list',
        'aria-label': 'Every check this page performs in this state',
      },
      checks.map((c) =>
        el('li', { role: 'listitem', 'data-check': c.pass ? 'pass' : 'fail' }, [
          verdict(c.pass ? 'ok' : 'alarm', c.pass ? 'HELD' : 'FAILED', {
            'data-verdict': 'check',
          }),
          el('span', { class: 'check-label' }, [c.label]),
          el('span', { class: 'check-detail' }, [c.detail]),
        ]),
      ),
    ),
    el('p', { class: 'fixture-turn' }, [
      'Every check above says the defence held. Here is the same program’s tables, read by an attack that never ran it:',
    ]),
  );
  if (bge) {
    fixtureHost.append(
      definitionList([
        [
          'BGE step A1 on round ' + bge.round + ', column ' + bge.column,
          bge.stripped
            ? `stripped all four output encodings to a GF(2)-affine map, in ${bge.elapsedMs} ms, using ${count(
                bge.evaluations,
              )} table evaluations and zero traces`
            : 'did not complete on these tables',
        ],
        [
          'What each one gave up',
          bge.bytes
            .map((b) => `row ${b.row}: a group of order ${b.groupOrder}, spread ${b.spreadBefore} → ${b.spreadAfter}`)
            .join(' · '),
        ],
      ]),
    );
  } else {
    fixtureHost.append(el('p', { class: 'aside-note' }, ['The algebraic step could not be run on these tables.']));
  }
  fixtureHost.append(
    negClaim('fixture'),
    el('p', { class: 'aside-note' }, [
      'And the honest other half: state 3 moves the problem rather than solving it. Something outside the program now holds F and G and has to apply them to every block — which is another piece of software, on some machine, with a secret in it.',
    ]),
  );
}

function placementSection(): HTMLElement {
  const node = section(
    'act-placement',
    'Act 5',
    'What actually stops it: where the encoding lives',
    'Chow specifies external encodings so a white-box program computes G ∘ AES ∘ F⁻¹ rather than AES. Whether that helps depends entirely on who holds F and G, and every state below is measured rather than asserted.',
  );
  const body = panel();
  body.append(
    el('p', {}, [
      'The thing most people expect is that turning external encodings on makes DCA fail. It does not. Bos et al. attacked an implementation with external encodings compiled into it and got the same result as without them, for a reason that is obvious once said: ',
      el('strong', {}, ['the attacker chooses the plaintext going in.']),
      ' If the encoder is inside the program, the attacker can always get from a plaintext they picked to the value the AES core sees, so the first-round hypotheses are as valid as ever.',
    ]),
    el('p', {}, [
      'What frustrated the attack in that paper was encodings that were ',
      el('em', {}, ['not part of the binary']),
      ' — held outside it, so the attacker could not relate real AES inputs or outputs to the computation they were watching. The paper scopes DCA to implementations applying at most a single remotely handled external encoding, and the rows below are that sentence, measured on this generator.',
    ]),
    el('div', { class: 'control-row' }, [
      button('sweep', 'Measure all seven combinations', 'plain', () => void runSweep()),
      el('p', { class: 'hint' }, [
        'Builds each placement from one seed — so the AES core is identical in every state — traces it at the current trace count, and attacks whichever side is worth attacking. Takes a few seconds per row.',
      ]),
    ]),
    sweepStatus,
    logHost,
    details('What this lab measured, and what the papers report', (out) => {
      out.append(
        el('p', {}, [
          'Two different kinds of number, kept apart on purpose. Measured here, over five instances at 384 traces, attacking the input side with all eight prediction bits: 12 to 16 bytes of 16 from the SubBytes-output target alone, 13 to 16 from the inverse target alone, 14 to 16 with the two combined, and 15 to 16 combined at 1,024 traces. Those are properties of this generator at those trace counts, not of Chow’s construction.',
        ]),
        el('p', {}, [
          'Reported by Bos, Hubain, Michiels and Teuwen (CHES 2016) about the implementations they attacked: 15 of 16 bytes from one target on one instance at 2,000 traces, 16 of 16 using the multiplicative-inverse target, and the full key whenever the two were combined across the instances they tested. Their figures, their implementations — and carried here at second hand, not re-read out of the paper by this lab. The numbers above them are the ones this page measured, and those are the ones it stands behind.',
        ]),
        el('p', {}, [
          'One result on this page is neither: attacking the OUTPUT side recovers only part of the last round key, and the part it recovers does not complete. The reason is structural and worth knowing. Chow’s first-round tables are 8 → 32, so a first-round key byte is exposed through eight encoded nibbles; his round-10 tables are 8 → 8, so a last-round key byte is exposed through two. Four times fewer places for a correlation to be. And inverting the AES-128 key schedule needs all sixteen bytes of k¹⁰, so a partial recovery of it yields nothing about the key.',
        ]),
      );
    }),
  );
  const fixture = panel('fixture-panel');
  fixture.append(el('h3', {}, ['The state the claim is about']), fixtureHost);
  node.append(body, fixture);
  return node;
}

// ── Act 6: BGE, the algebraic route ────────────────────────────────────────

const bgeOut = el('div', { id: 'bge-out' });
const bgeStatus = status('bge-status');
const bgeError = el('p', {
  id: 'bge-error',
  class: 'error',
  role: 'status',
  'aria-live': 'polite',
});
const roundSelect = select(
  'bge-round',
  [...Array(9).keys()].map((i) => ({
    value: String(i + 1),
    label: `round ${i + 1}`,
  })),
  '1',
  (value) => {
    state.bgeRound = Number(value);
  },
);
const columnSelect = select(
  'bge-column',
  [...Array(4).keys()].map((i) => ({ value: String(i), label: `column ${i}` })),
  '0',
  (value) => {
    state.bgeColumn = Number(value);
  },
);

async function runBge(): Promise<void> {
  bgeError.textContent = '';
  if (!state.build) {
    bgeError.textContent = 'NO_PROGRAM_BUILT — build the program first: this attack reads its tables.';
    return;
  }
  setBusy(true);
  bgeStatus.textContent = 'Composing the column and extracting the group…';
  try {
    const report = await ask<BgeReport & { id: number }>({
      kind: 'bge',
      round: state.bgeRound,
      column: state.bgeColumn,
    });
    state.bge = report;
    state.runs.bge += 1;
    bgeStatus.textContent = `Step A1 #${state.runs.bge} finished in ${report.elapsedMs} ms.`;
    renderBge(report);
  } catch (error) {
    const err = error as Error & { code?: string };
    state.bge = null;
    bgeStatus.textContent = '';
    bgeError.textContent = `${err.code ?? 'ERROR'} — ${err.message}`;
    renderBge(null);
  } finally {
    setBusy(false);
  }
}

function renderBge(report: BgeReport | null): void {
  clear(bgeOut);
  if (!report) {
    bgeOut.append(el('p', { class: 'placeholder' }, ['Step A1 has not been run. Press "Run step A1".']));
    return;
  }
  bgeOut.append(
    el(
      'div',
      { class: 'verdict-row', id: 'bge-verdict', 'data-bge-verdict': report.stripped ? 'stripped' : 'incomplete' },
      [
        verdict(
          report.stripped ? 'alarm' : 'warn',
          report.stripped ? 'ENCODINGS STRIPPED TO AFFINE' : 'STEP A1 DID NOT COMPLETE',
        ),
        el('span', { class: 'verdict-detail' }, [
          `Round ${report.round}, column ${report.column}. ${count(report.evaluations)} column evaluations, ${
            report.elapsedMs
          } ms, and not one traced encryption.`,
        ]),
      ],
    ),
    scroller(
      'BGE step A1 results per output byte',
      table(
        'What the tables gave up, output byte by output byte',
        [
          'Output byte',
          'Group order',
          'Every element an involution',
          'GF(2) basis',
          'Difference spread before',
          'after',
        ],
        report.bytes.map((b): Cell[] => [
          { text: `row ${b.row}` },
          { text: `${b.groupOrder}`, cls: 'mono' },
          {
            node: verdict(b.everyElementIsAnInvolution ? 'ok' : 'alarm', b.everyElementIsAnInvolution ? 'yes' : 'no'),
          },
          { text: `${b.basisSize} generators`, cls: 'mono' },
          { text: `${b.spreadBefore} values`, cls: 'mono' },
          {
            node: el('span', { class: 'cell-stack' }, [
              verdict(
                b.spreadAfter === 1 ? 'alarm' : 'warn',
                `${b.spreadAfter} value${b.spreadAfter === 1 ? '' : 's'}`,
              ),
              el('span', { class: 'cell-sub' }, [b.spreadAfter === 1 ? 'constant in x' : 'still varies']),
            ]),
          },
        ]),
      ),
    ),
    el('p', {}, [
      'The last two columns are the result, and they are checkable without knowing any secret. Take the column function with its second input byte fixed at two different values, and XOR the two outputs together. Before the recovered map is applied, that difference varies with the first input byte — the spread is the number of distinct values it takes over all 256. After the recovered map is applied it is one value, for every input. A constant difference is exactly what remains when only a GF(2)-affine part of the encoding is left, which is what step A1 claims to achieve.',
    ]),
  );
}

function bgeSection(): HTMLElement {
  const node = section(
    'act-bge',
    'Act 6',
    'The algebraic route, which needs no traces at all',
    'Billet, Gilbert and Ech-Chatbi attacked Chow’s construction in 2004 without running it once. Their first step is implemented here and runs live on the tables you built.',
  );
  const body = panel();
  body.append(
    el('p', {}, [
      'Compose one round’s tables for one column, from its four encoded input bytes to its four encoded output bytes. Every 4-bit internal encoding inside that column cancels, because each was applied by one table and undone by the next, and the whole 32-bit mixing bijection cancels too, because the Type III tables exist to remove it. What is left is',
    ]),
    el('p', { class: 'formula mono' }, ['R(x)ᵢ = Pᵢ( ⊕ₙ aᵢₙ · S( Qₙ⁻¹(xₙ) ⊕ kₙ ) )']),
    el('p', {}, [
      'with Pᵢ and Qₙ byte bijections and aᵢₙ the MixColumns coefficients. So Chow’s nibble width is not an algebraic obstacle at all: it is gone before this attack starts. That is the point of this act, and it is shown by computing it rather than said.',
    ]),
    details('How step A1 recovers an encoding — the derivation', (out) => {
      out.append(
        el('p', {}, [
          'Fix the second input byte at b and the other two at zero, and vary the first. Then fᵢᵇ(x) = Pᵢ( a · S(Q₀⁻¹(x)) ⊕ γᵢ(b) ), where γᵢ is a bijection of b because every MixColumns coefficient is non-zero. Compose fᵢᵇ with the inverse of fᵢ⁰ and the S-box drops out:',
        ]),
        el('p', { class: 'formula mono' }, ['fᵢᵇ ∘ (fᵢ⁰)⁻¹ = Pᵢ ∘ (⊕ δ) ∘ Pᵢ⁻¹']),
        el('p', {}, [
          'As b runs over all 256 values, δ runs over all of GF(2⁸), so that set of 256 permutations is a group isomorphic to (GF(2⁸), ⊕) — which the table above verifies rather than assumes: order 256, every element its own inverse, and eight generators spanning all of it. The group acts regularly on the bytes, so for each y there is exactly one element taking a fixed base point to y. Read off that element’s coordinates in the chosen basis and you have Pᵢ⁻¹ up to an unknown GF(2)-affine map, because a different basis choice is exactly a different invertible linear map.',
        ]),
        el('p', {}, [
          'That is the whole of step A1, and it costs 2¹⁶ evaluations of the column plus a few hundred thousand permutation operations. The page measures both.',
        ]),
      );
    }),
    el('div', { class: 'control-row' }, [
      field('bge-round', 'Round', roundSelect, 'Round 10 has no MixColumns and therefore no column to compose.'),
      field('bge-column', 'Column', columnSelect),
      button('run-bge', 'Run step A1', 'primary', () => void runBge()),
    ]),
    bgeError,
    bgeStatus,
    bgeOut,
  );
  const gate = panel('honest-panel');
  gate.append(
    el('h3', {}, ['What is NOT run in this page']),
    el('p', {}, [
      'Steps A2 and A3 of the BGE attack are not implemented here and are not animated here. A2 pins down the affine part step A1 leaves behind, using the affine-equivalence algorithm of Biryukov, De Cannière, Braeken and Preneel (EUROCRYPT 2003); A3 then extracts the round key. Nothing on this page does either, and nothing on this page pretends to.',
    ]),
    definitionList([
      [
        'Published work factor, whole attack',
        `2^${PUBLISHED_WORK_FACTORS.bge2004.exponent} with negligible memory — ${PUBLISHED_WORK_FACTORS.bge2004.source}`,
      ],
      [
        'Reduced by Lepoint et al.',
        `2^${PUBLISHED_WORK_FACTORS.lepoint2013.exponent} — ${PUBLISHED_WORK_FACTORS.lepoint2013.source}`,
      ],
      [
        'What the published attack covers',
        'Chow’s construction including the external input and output encodings Chow specifies — reported at second hand rather than read out of the paper here, and scoped to that construction rather than to arbitrary external encodings in other designs.',
      ],
      ['What runs here', 'Step A1 only, live, on the tables this page built, with zero traces.'],
    ]),
  );
  node.append(body, gate);
  return node;
}

// ── Act 7: what came after ─────────────────────────────────────────────────

function afterSection(): HTMLElement {
  const node = section(
    'act-after',
    'Act 7',
    'What came after',
    'Both attacks on this page are the early ones. Neither has got harder since.',
  );
  const body = panel();
  body.append(
    el('h3', {}, ['The algebraic line']),
    el('p', {}, [
      'Lepoint, Rivain, De Mulder, Roelse and Preneel, "Two Attacks on a White-Box AES Implementation" (SAC 2013), cut BGE’s work factor from 2³⁰ to 2²² and gave a second, different attack on the same construction. A work factor of 2²² is a few million operations — the sort of thing that finishes while you read this sentence.',
    ]),
    el('h3', {}, ['The statistical line']),
    el('p', {}, [
      'Rivain and Wang, in TCHES 2019(2), 225–255, analysed when and why DCA works against internal encodings, and broke encodings wider than 4 bits — including a byte-encoded implementation that plain DCA had failed on. So the lesson from Act 4 is not "nibbles leak, bytes are safe". Nibble width is why FIRST-ORDER difference of means works on Chow’s design; it is not the boundary of the attack family.',
    ]),
    el('h3', {}, ['Deliberately out of scope here']),
    el('p', {}, [
      'Commercial and obfuscated white-box designs. Masked white-box implementations. Differential fault analysis, which injects faults into the network instead of reading it. Higher-order DCA, mutual-information analysis and collision attacks beyond this reference to them. And any claim about the security of a white-box scheme this page does not build.',
    ]),
    details('Primary sources', (out) => {
      out.append(
        list([
          'S. Chow, P. Eisen, H. Johnson, P. C. van Oorschot. "White-Box Cryptography and an AES Implementation". SAC 2002. The construction this page builds.',
          'O. Billet, H. Gilbert, C. Ech-Chatbi. "Cryptanalysis of a White Box AES Implementation". SAC 2004, LNCS 3357, 227–240. Work factor 2³⁰, negligible memory. Step A1 is implemented here.',
          'J. W. Bos, C. Hubain, W. Michiels, P. Teuwen. "Differential Computation Analysis: Hiding Your White-Box Designs is Not Enough". CHES 2016, LNCS 9813, 215–236 (ePrint 2015/753). The attack in Act 4.',
          'T. Lepoint, M. Rivain, Y. De Mulder, P. Roelse, B. Preneel. "Two Attacks on a White-Box AES Implementation". SAC 2013. BGE reduced to 2²².',
          'M. Rivain, J. Wang. "Analysis and Improvement of Differential Computation Attacks against Internally-Encoded White-Box Implementations". TCHES 2019(2), 225–255.',
          'J. A. Muir. "A Tutorial on White-box AES". ePrint 2013/104. A secondary guide to Chow’s construction; Chow is cited for anything normative.',
          'FIPS PUB 197, Advanced Encryption Standard. NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation.',
        ]),
      );
    }),
  );
  node.append(body);
  return node;
}

// ── wiring ─────────────────────────────────────────────────────────────────

let busyDepth = 0;

/**
 * Disable the controls that start work while work is running.
 *
 * Not decoration: two builds in flight would leave the worker holding one
 * program while the page described another, and the page would then be reporting
 * numbers from two different instances side by side.
 */
function setBusy(busy: boolean): void {
  busyDepth = Math.max(0, busyDepth + (busy ? 1 : -1));
  const running = busyDepth > 0;
  for (const id of ['build', 'generate-key', 'trace', 'run-dca', 'run-bge', 'sweep']) {
    const node = document.getElementById(id);
    if (node instanceof HTMLButtonElement) node.disabled = running;
  }
  document.documentElement.toggleAttribute('data-busy', running);
}

seedInput.addEventListener('change', () => {
  state.seed = seedInput.value.trim();
});

main.append(
  scopeSection(),
  threatSection(),
  buildSection(),
  traceSection(),
  dcaSection(),
  placementSection(),
  bgeSection(),
  afterSection(),
);
app.append(
  el('footer', { class: 'scripture-footer' }, [
    el('p', {}, [
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    ]),
  ]),
);

renderTargetChecks();
renderBuild(null);
renderTrace(null);
renderDca(null);
renderLog();
renderBge(null);
void renderFixture();
// The arrival state is a built, verified program: Act 2 has something to show,
// and the acts after it have something to act on. Tracing and attacking stay the
// reader's move, because causing the failure is the point.
void runBuild();
