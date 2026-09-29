/**
 * The table-network diagram.
 *
 * It exists to show three things a paragraph cannot, and to avoid showing one
 * thing that would be a lie:
 *
 *  - WHERE THE ENCODINGS ARE. An encoded wire is drawn solid and opaque; an
 *    un-encoded one is drawn hollow. So "the value on this wire is a plain AES
 *    byte" is something a reader can see rather than take on trust.
 *  - WHERE THE PROGRAM ENDS. The dashed boundary is the attacker's reach. An
 *    external encoding held remotely is drawn OUTSIDE it; one compiled into the
 *    program is drawn inside, next to the box that undoes it.
 *  - WHERE THE TRACE COMES FROM. Every tap is on a table's output, which is what
 *    the tracer records.
 *
 *  And the lie it refuses: there is no box anywhere holding the key. The key is
 *  not stored in a Chow network at all. It survives only as the 256 values
 *  S(x ^ k) inside a T-box, and the diagram says exactly that where a "key" box
 *  would otherwise sit.
 */

import { svg } from './dom.js';
import type { EncodingPlacement } from '../wb/types.js';

const W = 940;
const H = 396;

interface Box {
  readonly x: number;
  readonly y: number;
  readonly w: number;
  readonly h: number;
}

function boxNode(b: Box, title: string, lines: readonly string[], cls: string): SVGElement {
  const g = svg('g', { class: `dg-box ${cls}` });
  g.append(svg('rect', { x: b.x, y: b.y, width: b.w, height: b.h, rx: 8, class: 'dg-rect' }));
  g.append(svg('text', { x: b.x + 10, y: b.y + 20, class: 'dg-title' }, [title]));
  lines.forEach((line, index) => {
    g.append(svg('text', { x: b.x + 10, y: b.y + 38 + index * 14, class: 'dg-line' }, [line]));
  });
  return g;
}

function arrow(x1: number, y1: number, x2: number, y2: number, encoded: boolean, label?: string): SVGElement {
  const g = svg('g', { class: `dg-wire ${encoded ? 'dg-encoded' : 'dg-clear'}` });
  g.append(svg('line', { x1, y1, x2, y2, class: 'dg-line-wire' }));
  g.append(svg('polygon', { points: `${x2},${y2} ${x2 - 8},${y2 - 5} ${x2 - 8},${y2 + 5}`, class: 'dg-head' }));
  if (label)
    g.append(svg('text', { x: (x1 + x2) / 2, y: y1 - 8, class: 'dg-wire-label', 'text-anchor': 'middle' }, [label]));
  return g;
}

function tap(x: number, y: number): SVGElement {
  const g = svg('g', { class: 'dg-tap' });
  g.append(svg('circle', { cx: x, cy: y, r: 4, class: 'dg-tap-dot' }));
  g.append(svg('text', { x, y: y + 18, class: 'dg-tap-label', 'text-anchor': 'middle' }, ['tap']));
  return g;
}

export interface DiagramView {
  readonly node: HTMLElement;
  update(placement: EncodingPlacement): void;
}

const DESCRIPTIONS: Record<EncodingPlacement, string> = {
  none: 'The program is plain AES. A plaintext byte enters the first Type II table un-encoded, and every wire after it is encoded. Nothing sits outside the program.',
  'compiled-in':
    'The program contains the encoder F as well as the Type IA tables that strip it, so both are inside the attacker’s reach and they cancel. The value the first round reads is still the reader’s chosen plaintext.',
  'remote-both':
    'F and G are held outside the program by a separate party. Every value crossing the boundary is encoded, so the attacker cannot say which plaintext any run corresponds to.',
  'remote-input':
    'F is held outside the program and G is not, so the value going in is encoded and the value coming out is a real AES ciphertext.',
  'remote-output':
    'G is held outside the program and F is not, so the value going in is a real AES plaintext and the value coming out is encoded.',
};

export function createDiagram(): DiagramView {
  const root = svg('svg', {
    viewBox: `0 0 ${W} ${H}`,
    class: 'diagram',
    role: 'img',
    'aria-label': DESCRIPTIONS.none,
    preserveAspectRatio: 'xMidYMid meet',
  });
  const caption = document.createElement('p');
  caption.className = 'figcaption';
  const node = document.createElement('div');
  node.className = 'figure diagram-wrap';
  node.append(root, caption);

  const update = (placement: EncodingPlacement): void => {
    while (root.firstChild) root.removeChild(root.firstChild);
    const inputRemote = placement === 'remote-both' || placement === 'remote-input';
    const outputRemote = placement === 'remote-both' || placement === 'remote-output';
    const hasIA = inputRemote || placement === 'compiled-in';
    const hasIB = outputRemote || placement === 'compiled-in';

    // The program boundary: everything inside it is readable by the attacker.
    root.append(
      svg('rect', { x: 150, y: 54, width: 776, height: 300, rx: 14, class: 'dg-boundary' }),
      svg('text', { x: 162, y: 46, class: 'dg-boundary-label' }, [
        'the program — every byte of this is readable, runnable and pausable by the attacker',
      ]),
    );

    // Outside: the remote party, or a note that nothing is outside.
    if (inputRemote || outputRemote) {
      root.append(
        boxNode(
          { x: 8, y: 96, w: 132, h: 96 },
          'encoding party',
          [
            'outside the program',
            inputRemote ? 'applies F on input' : 'applies nothing on input',
            outputRemote ? 'removes G on output' : 'passes output through',
          ],
          'dg-remote',
        ),
      );
      root.append(
        svg('text', { x: 8, y: 214, class: 'dg-note' }, ['something out here']),
        svg('text', { x: 8, y: 228, class: 'dg-note' }, ['must hold a secret']),
        svg('text', { x: 8, y: 242, class: 'dg-note' }, ['and apply it per block.']),
      );
    } else {
      root.append(
        svg('text', { x: 8, y: 120, class: 'dg-note' }, ['nothing is outside']),
        svg('text', { x: 8, y: 134, class: 'dg-note' }, ['the program.']),
      );
    }

    // The input wire. Encoded exactly when the input encoding is remote.
    root.append(arrow(140, 128, 168, 128, inputRemote, inputRemote ? 'F(P)' : 'P'));

    let x = 168;
    if (hasIA) {
      root.append(
        boxNode(
          { x, y: 90, w: 150, h: 76 },
          'Type IA × 16',
          ['8 → 128 each, plus a', '15-step XOR tree.', placement === 'compiled-in' ? 'F, then F⁻¹.' : 'strips F.'],
          'dg-ext',
        ),
      );
      root.append(tap(x + 75, 172));
      x += 162;
      root.append(arrow(x - 12, 128, x, 128, true));
    }

    root.append(
      boxNode(
        { x, y: 82, w: 172, h: 92 },
        'Type II × 4',
        ['S(x ⊕ k) for all 256 x,', 'then Tyᵢ and the 32-bit', 'mixing bijection MB.'],
        'dg-core',
      ),
    );
    root.append(
      svg('text', { x: x + 4, y: 190, class: 'dg-keynote' }, ['no box here holds k — only']),
      svg('text', { x: x + 4, y: 204, class: 'dg-keynote' }, ['these 256 outputs exist']),
    );
    root.append(tap(x + 86, 180));
    const t2Right = x + 172;

    root.append(arrow(t2Right, 128, t2Right + 24, 128, true, '32 bits'));
    x = t2Right + 24;
    root.append(
      boxNode(
        { x, y: 90, w: 128, h: 76 },
        'Type IV × 24',
        ['nibble XORs summing', 'the four 32-bit', 'words to MB·MixColumns.'],
        'dg-core',
      ),
    );
    root.append(tap(x + 64, 172));
    x += 128;
    root.append(arrow(x, 128, x + 24, 128, true));
    x += 24;
    root.append(
      boxNode(
        { x, y: 90, w: 128, h: 76 },
        'Type III × 4',
        ['removes MB, applies', 'the next round’s 8-bit', 'bijections. + 24 Type IV.'],
        'dg-core',
      ),
    );
    root.append(tap(x + 64, 172));
    x += 128;

    // Round 10 and the output side, on the lower track.
    root.append(
      svg('path', { d: `M ${x} 128 H ${x + 20} V 268 H 300 V 292`, class: 'dg-turn' }),
      svg('text', { x: x - 210, y: 258, class: 'dg-wire-label' }, ['… rounds 2 to 9, then round 10 …']),
    );
    root.append(
      boxNode({ x: 236, y: 292, w: 150, h: 54 }, 'Type V × 16', ['8 → 8. Round 10 has', 'no MixColumns.'], 'dg-core'),
    );
    let ox = 386;
    root.append(arrow(ox, 318, ox + 24, 318, true));
    ox += 24;
    if (hasIB) {
      root.append(
        boxNode(
          { x: ox, y: 292, w: 150, h: 54 },
          'Type IB × 16',
          [
            '8 → 128 each, plus a',
            placement === 'compiled-in' ? '15-step tree. G, then G⁻¹.' : '15-step tree. Applies G.',
          ],
          'dg-ext',
        ),
      );
      ox += 162;
      root.append(arrow(ox - 12, 318, ox, 318, outputRemote));
    }
    root.append(
      svg('text', { x: ox + 8, y: 314, class: 'dg-line' }, [
        outputRemote ? 'G(C) leaves the program' : 'C leaves the program',
      ]),
      svg('text', { x: ox + 8, y: 330, class: 'dg-line' }, [
        outputRemote ? '— not a ciphertext the' : '— a real AES ciphertext.',
      ]),
      outputRemote ? svg('text', { x: ox + 8, y: 344, class: 'dg-line' }, ['attacker can use.']) : svg('g', {}),
    );

    // The legend, which is what makes "opaque means encoded" readable.
    const legend = svg('g', { class: 'dg-legend' });
    legend.append(svg('line', { x1: 160, y1: 372, x2: 196, y2: 372, class: 'dg-legend-encoded' }));
    legend.append(svg('text', { x: 204, y: 376, class: 'dg-line' }, ['encoded — solid']));
    legend.append(svg('line', { x1: 330, y1: 372, x2: 366, y2: 372, class: 'dg-legend-clear' }));
    legend.append(svg('text', { x: 374, y: 376, class: 'dg-line' }, ['not encoded — hollow']));
    legend.append(svg('circle', { cx: 540, cy: 372, r: 4, class: 'dg-tap-dot' }));
    legend.append(svg('text', { x: 552, y: 376, class: 'dg-line' }, ['tap — the tracer records this table’s output']));
    root.append(legend);

    root.setAttribute('aria-label', `Diagram of one column of round 1. ${DESCRIPTIONS[placement]}`);
    caption.textContent = DESCRIPTIONS[placement];
  };

  update('none');
  return { node, update };
}
