/**
 * Element helpers, shaped so the accessibility rules are satisfied by
 * construction rather than remembered.
 *
 * Three of them exist specifically because the WCAG gate in `e2e/` measures the
 * outcome rather than the intention:
 *
 *  `scroller`  attaches `role="region"`, `tabindex="0"` and an `aria-label`
 *              together, so a scrolling region cannot be born without a keyboard
 *              route (WCAG 2.1.1) or a name.
 *  `figure`    pairs a `<canvas>` with `role="img"` and a label that is REWRITTEN
 *              from the data every time it is drawn, because a canvas is opaque
 *              to a screen reader and a stale label is worse than none.
 *  `list`      puts `role="list"` on the container and `role="listitem"` on every
 *              child at once -- `list-style: none` is what makes Safari drop a
 *              list's semantics, and this lab styles several that way.
 */

type Attrs = Record<string, string | number | boolean | null | undefined>;
type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = String(value);
    else if (key === 'text') node.textContent = String(value);
    else if (key === 'html') throw new Error('this lab never sets innerHTML');
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function svg(tag: string, attrs: Attrs = {}, children: (SVGElement | string)[] = []): SVGElement {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    node.setAttribute(key, String(value));
  }
  for (const child of children) node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** A horizontally scrolling region that a keyboard can reach and a reader can name. */
export function scroller(label: string, child: Node): HTMLElement {
  return el('div', { class: 'scroller', role: 'region', tabindex: '0', 'aria-label': label }, [child]);
}

/** A live region for asynchronous output. */
export function status(id: string, extraClass = ''): HTMLElement {
  return el('p', { id, class: `status ${extraClass}`.trim(), role: 'status', 'aria-live': 'polite' });
}

export function section(id: string, actLabel: string, heading: string, lead: string): HTMLElement {
  return el('section', { id, class: 'act', 'aria-labelledby': `${id}-h` }, [
    el('p', { class: 'act-kicker' }, [actLabel]),
    el('h2', { id: `${id}-h` }, [heading]),
    el('p', { class: 'act-lead' }, [lead]),
  ]);
}

export function panel(extraClass = ''): HTMLElement {
  return el('div', { class: `panel ${extraClass}`.trim() });
}

export function field(id: string, labelText: string, control: HTMLElement, hint?: string): HTMLElement {
  return el('div', { class: 'field' }, [
    el('label', { for: id }, [labelText]),
    control,
    hint ? el('p', { class: 'hint', id: `${id}-hint` }, [hint]) : null,
  ]);
}

export interface RadioOption {
  readonly value: string;
  readonly label: string;
  readonly note?: string;
  readonly group?: string;
}

export function radioGroup(
  name: string,
  legend: string,
  options: readonly RadioOption[],
  selected: string,
  onChange: (value: string) => void,
): HTMLElement {
  const fs = el('fieldset', { class: 'radios' }, [el('legend', {}, [legend])]);
  let lastGroup: string | undefined;
  for (const option of options) {
    if (option.group && option.group !== lastGroup) {
      fs.append(el('p', { class: 'radio-group-label' }, [option.group]));
      lastGroup = option.group;
    }
    const id = `${name}-${option.value}`;
    const input = el('input', {
      type: 'radio',
      name,
      id,
      value: option.value,
      checked: option.value === selected,
    });
    input.addEventListener('change', () => {
      if (input.checked) onChange(option.value);
    });
    fs.append(
      el('div', { class: 'radio' }, [
        input,
        el('label', { for: id }, [option.label, option.note ? el('span', { class: 'radio-note' }, [option.note]) : null]),
      ]),
    );
  }
  return fs;
}

export function checkbox(
  id: string,
  labelText: string,
  checked: boolean,
  onChange: (value: boolean) => void,
): HTMLElement {
  const input = el('input', { type: 'checkbox', id, checked });
  input.addEventListener('change', () => onChange(input.checked));
  return el('div', { class: 'check' }, [input, el('label', { for: id }, [labelText])]);
}

export function select(
  id: string,
  options: readonly { value: string; label: string }[],
  selected: string,
  onChange: (value: string) => void,
): HTMLSelectElement {
  const node = el('select', { id, class: 'styled-select' });
  for (const option of options) {
    node.append(el('option', { value: option.value, selected: option.value === selected }, [option.label]));
  }
  node.addEventListener('change', () => onChange(node.value));
  return node;
}

export function button(id: string, label: string, kind: 'primary' | 'plain' | 'danger', onClick: () => void): HTMLButtonElement {
  const node = el('button', { id, type: 'button', class: `btn ${kind}` }, [label]);
  node.addEventListener('click', onClick);
  return node;
}

export interface Cell {
  readonly text?: string;
  readonly header?: boolean;
  readonly cls?: string;
  readonly node?: Node;
}

export function table(caption: string, headers: readonly string[], rows: readonly (readonly Cell[])[], cls = ''): HTMLElement {
  const thead = el('thead', {}, [
    el(
      'tr',
      {},
      headers.map((h) => el('th', { scope: 'col' }, [h])),
    ),
  ]);
  const tbody = el(
    'tbody',
    {},
    rows.map((row) =>
      el(
        'tr',
        {},
        row.map((cell, index) =>
          cell.header || index === 0
            ? el('th', { scope: 'row', class: cell.cls ?? '' }, [cell.node ?? cell.text ?? ''])
            : el('td', { class: cell.cls ?? '' }, [cell.node ?? cell.text ?? '']),
        ),
      ),
    ),
  );
  return el('table', { class: `matrix ${cls}`.trim() }, [el('caption', {}, [caption]), thead, tbody]);
}

export function definitionList(pairs: readonly (readonly [string, string | Node])[]): HTMLElement {
  const dl = el('dl', { class: 'defs' });
  for (const [term, value] of pairs) {
    dl.append(el('dt', {}, [term]), el('dd', {}, [typeof value === 'string' ? value : value]));
  }
  return dl;
}

/** A list whose bullets are suppressed, with its semantics restored explicitly. */
export function list(items: readonly (string | Node)[], cls = ''): HTMLElement {
  if (items.length === 0) throw new Error('an empty role="list" fails aria-required-children; render a paragraph');
  return el(
    'ul',
    { class: `plain-list ${cls}`.trim(), role: 'list' },
    items.map((item) => el('li', { role: 'listitem' }, [typeof item === 'string' ? item : item])),
  );
}

/**
 * State is conveyed three ways at once -- an icon, a word, and a colour -- so
 * removing any one of them still leaves it readable (WCAG 1.4.1).
 */
export type VerdictTone = 'ok' | 'alarm' | 'warn' | 'info';

const GLYPH: Record<VerdictTone, string> = { ok: '✓', alarm: '✕', warn: '⚠', info: '●' };

export function verdict(tone: VerdictTone, label: string, attrs: Attrs = {}): HTMLElement {
  return el('span', { class: `pill pill-${tone}`, ...attrs }, [
    el('span', { class: 'pill-glyph', 'aria-hidden': 'true' }, [GLYPH[tone]]),
    el('span', { class: 'pill-text' }, [label]),
  ]);
}

export function details(summaryText: string, build: (body: HTMLElement) => void): HTMLElement {
  const body = el('div', { class: 'more-body' });
  build(body);
  return el('details', { class: 'more' }, [el('summary', {}, [summaryText]), body]);
}

export interface Figure {
  readonly wrap: HTMLElement;
  readonly canvas: HTMLCanvasElement;
  describe(text: string): void;
}

/**
 * A canvas plus the text that stands in for it.
 *
 * `describe` is called from the draw path every time, so the label is a
 * description of what was actually painted. A canvas whose label was written
 * once, in markup, is a canvas that lies as soon as the data changes.
 */
export function figure(id: string, scrollLabel: string | null, caption: string): Figure {
  const canvas = el('canvas', { id, role: 'img', 'aria-label': caption, class: 'plot' });
  const inner = scrollLabel ? scroller(scrollLabel, canvas) : canvas;
  const wrap = el('div', { class: 'figure' }, [inner, el('p', { class: 'figcaption', id: `${id}-cap` }, [caption])]);
  return {
    wrap,
    canvas,
    describe(text: string): void {
      canvas.setAttribute('aria-label', text);
      const cap = document.getElementById(`${id}-cap`);
      if (cap) cap.textContent = text;
    },
  };
}
