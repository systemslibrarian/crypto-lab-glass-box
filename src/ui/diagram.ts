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
/**
 * The narrow layout's canvas. Tall rather than wide, because the alternative --
 * scaling the 940-unit wide diagram into a 343 CSS px phone column -- renders
 * its 10px labels at about 3.6 CSS px, which is not a small diagram but an
 * unreadable one. Below `NARROW_AT` the same content is laid out down the page
 * instead, at the same text size it has on a desktop.
 */
const NARROW_W = 380;
const NARROW_H = 1000;
const NARROW_AT = 760;

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

function arrowDown(x: number, y1: number, y2: number, encoded: boolean, label?: string): SVGElement {
  const g = svg('g', { class: `dg-wire ${encoded ? 'dg-encoded' : 'dg-clear'}` });
  g.append(svg('line', { x1: x, y1, x2: x, y2, class: 'dg-line-wire' }));
  g.append(svg('polygon', { points: `${x},${y2} ${x - 5},${y2 - 8} ${x + 5},${y2 - 8}`, class: 'dg-head' }));
  if (label) g.append(svg('text', { x: x + 12, y: (y1 + y2) / 2 + 4, class: 'dg-wire-label' }, [label]));
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

/**
 * The same diagram, laid out down the page.
 *
 * Not a simplification: every box, every wire, the program boundary, the remote
 * party, the tap markers and the legend are all here, and the type is the size it
 * is on a desktop. Only the arrangement changes, because at 390 CSS px the wide
 * arrangement is legible to nobody.
 */
function drawNarrow(root: SVGElement, placement: EncodingPlacement): void {
  const inputRemote = placement === 'remote-both' || placement === 'remote-input';
  const outputRemote = placement === 'remote-both' || placement === 'remote-output';
  const hasIA = inputRemote || placement === 'compiled-in';
  const hasIB = outputRemote || placement === 'compiled-in';

  const x = 26;
  const w = NARROW_W - 52;
  let y = 8;

  if (inputRemote || outputRemote) {
    root.append(
      boxNode(
        { x, y, w, h: 74 },
        'encoding party \u2014 outside the program',
        [
          inputRemote ? 'applies F to every input' : 'passes the input through',
          outputRemote ? 'removes G from every output' : 'passes the output through',
          'holds a secret, on some other machine',
        ],
        'dg-remote',
      ),
    );
    y += 74;
  } else {
    root.append(svg('text', { x, y: y + 12, class: 'dg-note' }, ['Nothing is outside the program.']));
    y += 22;
  }
  root.append(arrowDown(x + 28, y, y + 30, inputRemote, inputRemote ? 'F(P)' : 'P'));
  y += 30;

  // The boundary encloses everything from here to the last core box.
  const boundaryTop = y;
  const boxes: { title: string; lines: string[]; cls: string; encodedOut: boolean; tap: boolean }[] = [];
  if (hasIA) {
    boxes.push({
      title: 'Type IA \u00d7 16, 8 \u2192 128',
      lines: [
        'plus a 15-step XOR tree',
        placement === 'compiled-in' ? 'F, then F\u207b\u00b9 \u2014 they cancel' : 'strips F',
      ],
      cls: 'dg-ext',
      encodedOut: true,
      tap: true,
    });
  }
  boxes.push({
    title: 'Type II \u00d7 4, 8 \u2192 32',
    lines: [
      'S(x \u2295 k) for all 256 x, then',
      'Ty\u1d62 and the 32-bit bijection MB',
      'no box holds k \u2014 only these 256',
    ],
    cls: 'dg-core',
    encodedOut: true,
    tap: true,
  });
  boxes.push({
    title: 'Type IV \u00d7 24, 8 \u2192 4',
    lines: ['nibble XORs summing the four', 'words to MB\u00b7MixColumns'],
    cls: 'dg-core',
    encodedOut: true,
    tap: true,
  });
  boxes.push({
    title: 'Type III \u00d7 4, + 24 Type IV',
    lines: ['removes MB, applies the next', 'round\u2019s 8-bit bijections'],
    cls: 'dg-core',
    encodedOut: true,
    tap: true,
  });
  boxes.push({
    title: 'rounds 2 to 9, then round 10',
    lines: ['Type V \u00d7 16, 8 \u2192 8', 'round 10 has no MixColumns'],
    cls: 'dg-core',
    encodedOut: true,
    tap: false,
  });
  if (hasIB) {
    boxes.push({
      title: 'Type IB \u00d7 16, 8 \u2192 128',
      lines: [
        'plus a 15-step XOR tree',
        placement === 'compiled-in' ? 'G, then G\u207b\u00b9 \u2014 they cancel' : 'applies G',
      ],
      cls: 'dg-ext',
      encodedOut: outputRemote,
      tap: true,
    });
  }

  for (let i = 0; i < boxes.length; i++) {
    const b = boxes[i];
    const h = 26 + b.lines.length * 14;
    root.append(boxNode({ x, y, w, h }, b.title, b.lines, b.cls));
    if (b.tap) root.append(tap(x + w - 16, y + h - 10));
    y += h;
    const last = i === boxes.length - 1;
    root.append(arrowDown(x + 28, y, y + 26, last ? b.encodedOut : true));
    y += 26;
  }
  const boundaryBottom = y - 26;
  root.insertBefore(
    svg('rect', {
      x: x - 14,
      y: boundaryTop - 6,
      width: w + 28,
      height: boundaryBottom - boundaryTop + 12,
      rx: 12,
      class: 'dg-boundary',
    }),
    root.firstChild,
  );
  root.append(
    svg('text', { x: x - 14, y: boundaryTop - 12, class: 'dg-boundary-label' }, [
      'the program \u2014 all of it readable by the attacker',
    ]),
    svg('text', { x, y: y + 14, class: 'dg-line' }, [
      outputRemote ? 'G(C) leaves \u2014 not a usable ciphertext' : 'C leaves \u2014 a real AES ciphertext',
    ]),
  );
  y += 40;

  const legend = svg('g', { class: 'dg-legend' });
  legend.append(svg('line', { x1: x, y1: y, x2: x + 26, y2: y, class: 'dg-legend-encoded' }));
  legend.append(svg('text', { x: x + 34, y: y + 4, class: 'dg-line' }, ['encoded \u2014 solid']));
  legend.append(svg('line', { x1: x, y1: y + 20, x2: x + 26, y2: y + 20, class: 'dg-legend-clear' }));
  legend.append(svg('text', { x: x + 34, y: y + 24, class: 'dg-line' }, ['not encoded \u2014 hollow']));
  legend.append(svg('circle', { cx: x + 13, cy: y + 40, r: 4, class: 'dg-tap-dot' }));
  legend.append(svg('text', { x: x + 34, y: y + 44, class: 'dg-line' }, ['tap \u2014 the tracer records this output']));
  root.append(legend);
  // Sized to the content, not to a fixed canvas: the number of boxes depends on
  // the placement, and a floor would leave a column of empty pixels under the
  // shortest one.
  root.setAttribute('viewBox', `0 0 ${NARROW_W} ${y + 56}`);
}

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

  /**
   * Which layout to draw. A media query rather than a container measurement,
   * because the WCAG gate sets a viewport before it navigates and this has to
   * be the same decision the reader's browser makes -- and because the choice is
   * about how much horizontal room the TYPE has, which is a viewport property.
   */
  const narrow = (): boolean =>
    typeof matchMedia === 'function' ? matchMedia(`(max-width: ${NARROW_AT - 1}px)`).matches : false;

  let lastPlacement: EncodingPlacement = 'none';

  const update = (placement: EncodingPlacement): void => {
    lastPlacement = placement;
    while (root.firstChild) root.removeChild(root.firstChild);
    if (narrow()) {
      root.setAttribute('viewBox', `0 0 ${NARROW_W} ${NARROW_H}`);
      drawNarrow(root, placement);
      root.setAttribute(
        'aria-label',
        `Diagram of one column of round 1, laid out vertically. ${DESCRIPTIONS[placement]}`,
      );
      caption.textContent = DESCRIPTIONS[placement];
      return;
    }
    root.setAttribute('viewBox', `0 0 ${W} ${H}`);
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

  // Redraw on a width change, so a reader who rotates a phone or resizes a
  // window gets the layout that fits rather than the one they arrived with.
  if (typeof matchMedia === 'function') {
    const query = matchMedia(`(max-width: ${NARROW_AT - 1}px)`);
    const onChange = (): void => update(lastPlacement);
    if (typeof query.addEventListener === 'function') query.addEventListener('change', onChange);
  }

  update('none');
  return { node, update };
}
