/**
 * Canvas drawing: the trace heatmap, the peak-per-guess plot and the
 * difference-of-means curves.
 *
 * Every one of these is drawn FROM THE COMPUTED DATA and nothing else. There is
 * no idle animation anywhere in this lab and no motion that represents nothing:
 * a canvas here repaints when a computation finishes, and otherwise it sits
 * still.
 *
 * A canvas is invisible to a screen reader, so each of these returns the sentence
 * its caller writes into the figure's label -- built from the same numbers that
 * were drawn, so it cannot drift from the picture.
 */

import type { DcaReport, HeatmapReport } from '../protocol.js';

const INK_BG = '#080c11';
const INK_GRID = '#27333f';
const ACCENT = '#67e8f9';
const ALARM = '#ff8b8b';
const FAINT = 'rgba(169, 184, 198, 0.16)';

function sized(canvas: HTMLCanvasElement, width: number, height: number): CanvasRenderingContext2D {
  canvas.width = width;
  canvas.height = height;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('this browser did not give the page a 2D canvas context');
  ctx.imageSmoothingEnabled = false;
  ctx.fillStyle = INK_BG;
  ctx.fillRect(0, 0, width, height);
  return ctx;
}

/**
 * Trace bits to pixels.
 *
 * A cool near-white for a 1 and a near-black for a 0, rather than a saturated
 * accent: a full-strength hue over a megapixel of random bits reads as glare and
 * hides exactly the local differences these pictures exist to show.
 */
function paintBits(source: Uint8Array, rows: number, cols: number): ImageData {
  const image = new ImageData(cols, rows);
  const data = image.data;
  for (let i = 0; i < rows * cols; i++) {
    const on = source[i] > 128;
    data[i * 4] = on ? 186 : 15;
    data[i * 4 + 1] = on ? 208 : 21;
    data[i * 4 + 2] = on ? 220 : 28;
    data[i * 4 + 3] = 255;
  }
  return image;
}

function blit(target: CanvasRenderingContext2D, image: ImageData, width: number, height: number): void {
  const staging = document.createElement('canvas');
  staging.width = image.width;
  staging.height = image.height;
  const sctx = staging.getContext('2d');
  if (!sctx) throw new Error('this browser did not give the page a 2D canvas context');
  sctx.putImageData(image, 0, 0);
  target.imageSmoothingEnabled = false;
  target.drawImage(staging, 0, 0, image.width, image.height, 0, 0, width, height);
}

/**
 * The whole recording, one pixel per sample, inside a scroller.
 *
 * Drawn at native width on purpose, with the round boundaries marked from the
 * program's own segment map rather than from anything visible in the pixels --
 * because nothing IS visible in the pixels, and saying so is the point. Every
 * value on every wire is encoded, so a recording of lookup OUTPUTS looks like
 * noise. A real address trace does show the round structure, because table base
 * addresses repeat; that is a genuine difference between the two kinds of trace
 * and this picture is where a reader meets it.
 */
export function drawTraceHeatmap(
  canvas: HTMLCanvasElement,
  report: HeatmapReport,
  marks: readonly { label: string; startBit: number }[] = [],
): string {
  const rowScale = Math.max(1, Math.min(3, Math.floor(360 / Math.max(report.rows, 1))));
  const height = report.rows * rowScale;
  const axis = 16;
  const ctx = sized(canvas, report.cols, height + axis);
  blit(ctx, paintBits(report.full, report.rows, report.cols), report.cols, height);

  let marked = 0;
  ctx.font = '10px ui-monospace, monospace';
  for (const mark of marks) {
    const x = mark.startBit - report.startSample;
    if (x < 0 || x >= report.cols) continue;
    marked++;
    ctx.strokeStyle = ACCENT;
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(x + 0.5, 0);
    ctx.lineTo(x + 0.5, height);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = ACCENT;
    ctx.fillText(mark.label, x + 3, height + 12);
  }
  if (report.splitRow !== null) {
    ctx.strokeStyle = ACCENT;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, report.splitRow * rowScale + 0.5);
    ctx.lineTo(report.cols, report.splitRow * rowScale + 0.5);
    ctx.stroke();
  }
  return (
    `Trace heatmap: ${report.rows} of ${report.rowsAvailable} traces down, ` +
    `${report.cols} recorded samples across starting at sample ${report.startSample}, ` +
    `light for a 1 bit and dark for a 0` +
    (marked > 0 ? `, with ${marked} round boundaries marked from the program's segment map` : '') +
    '. It looks like noise because it is: every wire in the network carries an encoded value, so no pixel here is a plain AES bit and no amount of looking will find the key in it.'
  );
}

/**
 * The zoomed strip around the leaking sample, and the statistic itself.
 *
 * This is the picture the whole lab is about. The rows are split by the bit a
 * hypothesis predicts, with a gap between the halves so the split is structural
 * rather than a line someone has to notice. Beneath it, for every sample in the
 * strip, the fraction of 1 bits in each half is drawn as a pair of bars -- which
 * is the difference of means, not an illustration of it. Under the right
 * hypothesis one pair pulls apart. Under a wrong one every pair stays level.
 */
export function drawFocusHeatmap(canvas: HTMLCanvasElement, report: HeatmapReport, focusSample: number): string {
  if (!report.focus || report.focusCols === 0 || !report.meanZero || !report.meanOne) {
    sized(canvas, 360, 60);
    return 'No sample is in focus yet: run the attack, and this strip will centre on the sample it peaked at.';
  }
  const cols = report.focusCols;
  const cellW = Math.max(6, Math.min(34, Math.floor(600 / cols)));
  const cellH = Math.max(2, Math.min(4, Math.floor(300 / Math.max(report.rows, 1))));
  const width = cols * cellW;
  const gap = report.splitRow === null ? 0 : 10;
  const stripH = report.rows * cellH + gap;
  const barsH = 74;
  const axis = 16;
  const ctx = sized(canvas, width, stripH + barsH + axis);

  const split = report.splitRow ?? report.rows;
  const image = paintBits(report.focus, report.rows, cols);
  if (gap === 0) {
    blit(ctx, image, width, stripH);
  } else {
    // Two blits, so the gap is real space rather than a drawn line.
    const top = new ImageData(cols, Math.max(split, 1));
    top.data.set(image.data.subarray(0, Math.max(split, 1) * cols * 4));
    blit(ctx, top, width, split * cellH);
    const bottomRows = report.rows - split;
    if (bottomRows > 0) {
      const bottom = new ImageData(cols, bottomRows);
      bottom.data.set(image.data.subarray(split * cols * 4));
      const staging = document.createElement('canvas');
      staging.width = cols;
      staging.height = bottomRows;
      const sctx = staging.getContext('2d');
      if (!sctx) throw new Error('this browser did not give the page a 2D canvas context');
      sctx.putImageData(bottom, 0, 0);
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(staging, 0, 0, cols, bottomRows, 0, split * cellH + gap, width, bottomRows * cellH);
    }
  }

  if (gap > 0) {
    ctx.strokeStyle = INK_GRID;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, split * cellH + gap / 2 + 0.5);
    ctx.lineTo(width, split * cellH + gap / 2 + 0.5);
    ctx.stroke();
  }
  const column = focusSample - report.focusStartSample;
  if (column >= 0 && column < cols) {
    ctx.strokeStyle = ACCENT;
    ctx.lineWidth = 2;
    ctx.strokeRect(column * cellW - 1, 0, cellW + 2, stripH);
  }

  // The two means, per sample.
  const base = stripH + barsH - 8;
  ctx.strokeStyle = INK_GRID;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, base + 0.5);
  ctx.lineTo(width, base + 0.5);
  ctx.stroke();
  const barW = Math.max(2, Math.floor(cellW / 2) - 2);
  let widest = 0;
  let widestColumn = 0;
  for (let c = 0; c < cols; c++) {
    const zero = report.meanZero[c];
    const one = report.meanOne[c];
    const spread = Math.abs(zero - one);
    if (spread > widest) {
      widest = spread;
      widestColumn = c;
    }
    const scale = barsH - 18;
    ctx.fillStyle = 'rgba(169, 184, 198, 0.85)';
    ctx.fillRect(c * cellW + 1, base - zero * scale, barW, zero * scale);
    ctx.fillStyle = ACCENT;
    ctx.fillRect(c * cellW + 2 + barW, base - one * scale, barW, one * scale);
  }
  if (column >= 0 && column < cols) {
    ctx.strokeStyle = ACCENT;
    ctx.lineWidth = 2;
    ctx.strokeRect(column * cellW - 1, stripH + 2, cellW + 2, barsH - 12);
  }
  ctx.font = '10px ui-monospace, monospace';
  ctx.fillStyle = '#a9b8c6';
  ctx.fillText(`sample ${focusSample}`, Math.max(0, Math.min(width - 72, column * cellW - 16)), base + 12);

  const at = column >= 0 && column < cols ? column : widestColumn;
  const delta = Math.abs(report.meanZero[at] - report.meanOne[at]);
  return (
    `Zoomed trace strip and the statistic taken from it. Samples ${report.focusStartSample} to ` +
    `${report.focusStartSample + cols - 1}, ${report.rows} of the traces drawn as rows` +
    (report.sortedBy
      ? `, split by the predicted bit (${report.sortedBy}): ${report.groupZeroTraces} traces above the gap predict 0 and ` +
        `${report.groupOneTraces} below predict 1. `
      : ', in recording order. ') +
    `The bar pairs beneath each sample are the fraction of 1 bits in each half, over every trace. ` +
    `At sample ${focusSample} those fractions are ${report.meanZero[at].toFixed(3)} and ${report.meanOne[at].toFixed(3)}, ` +
    `a difference of ${delta.toFixed(3)}. ` +
    (delta > 0.08
      ? 'That gap is the leak: the hypothesis predicts something real about what the program wrote at that sample.'
      : 'The pairs are level, so this hypothesis predicts nothing about what the program wrote.')
  );
}

/**
 * Peak difference of means for each of the 256 hypotheses. One bar per guess.
 *
 * The winner is only highlighted because the computation chose it, and the true
 * key byte is only marked once the comparison has happened -- which it does
 * after `runDca` has committed its answer (invariant I3).
 */
export function drawPeaksPerGuess(
  canvas: HTMLCanvasElement,
  byteReport: DcaReport['bytes'][number],
  revealTruth: boolean,
): string {
  const barW = 4;
  const width = 256 * barW;
  const height = 210;
  const base = height - 26;
  const ctx = sized(canvas, width, height);
  const peaks = byteReport.peaks;
  let max = 0;
  for (let g = 0; g < 256; g++) max = Math.max(max, peaks[g]);
  const scale = max > 0 ? (base - 14) / max : 0;

  ctx.strokeStyle = INK_GRID;
  ctx.lineWidth = 1;
  for (let f = 1; f <= 4; f++) {
    const y = base - ((base - 14) * f) / 4;
    ctx.beginPath();
    ctx.moveTo(0, y + 0.5);
    ctx.lineTo(width, y + 0.5);
    ctx.stroke();
  }

  for (let g = 0; g < 256; g++) {
    const h = peaks[g] * scale;
    ctx.fillStyle = g === byteReport.guess ? ACCENT : 'rgba(169, 184, 198, 0.5)';
    ctx.fillRect(g * barW, base - h, barW - 1, h);
  }

  // The runner-up line. Without it the chart is 256 tallish bars and the eye
  // cannot tell which one won; with it, exactly one bar is above the line, which
  // is the whole result. It is drawn AT the second-best score, so it states a
  // measured value rather than a chosen threshold.
  const runnerY = base - byteReport.runnerUp * scale;
  ctx.strokeStyle = '#ffc76b';
  ctx.setLineDash([5, 4]);
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(0, runnerY + 0.5);
  ctx.lineTo(width, runnerY + 0.5);
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.font = '11px ui-monospace, monospace';
  ctx.fillStyle = '#ffc76b';
  ctx.fillText('second best', 6, Math.max(11, runnerY - 4));

  const winnerX = byteReport.guess * barW + barW / 2;
  ctx.fillStyle = ACCENT;
  ctx.beginPath();
  ctx.moveTo(winnerX, base - byteReport.peak * scale - 4);
  ctx.lineTo(winnerX - 5, base - byteReport.peak * scale - 12);
  ctx.lineTo(winnerX + 5, base - byteReport.peak * scale - 12);
  ctx.closePath();
  ctx.fill();

  if (revealTruth) {
    const x = byteReport.truth * barW;
    ctx.strokeStyle = byteReport.correct ? ACCENT : ALARM;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(x + barW / 2, base + 2);
    ctx.lineTo(x + barW / 2, base + 10);
    ctx.stroke();
    ctx.fillStyle = byteReport.correct ? ACCENT : ALARM;
    ctx.fillText('true byte', Math.min(width - 62, Math.max(2, x - 22)), height - 6);
  }
  const hex = (v: number): string => `0x${v.toString(16).padStart(2, '0')}`;
  return (
    `Peak difference of means for each of the 256 candidate values of key byte ${byteReport.index}, ` +
    `one bar per candidate with the dashed line at the second-best score. ` +
    `The tallest bar is ${hex(byteReport.guess)} at ${byteReport.peak.toFixed(4)}; the second best is ` +
    `${hex(byteReport.runnerUpGuess)} at ${byteReport.runnerUp.toFixed(4)}, ` +
    `so the winner stands ${(byteReport.margin * 100).toFixed(0)} per cent above it.` +
    (revealTruth
      ? ` The true byte ${hex(byteReport.truth)} is ticked on the axis, and the attack ${
          byteReport.correct ? 'found it' : 'did not find it'
        }.`
      : ' The true byte is not marked: the attack has not been compared with it yet.')
  );
}

/**
 * All 256 difference-of-means curves across the window, faint, with the winner
 * drawn over them.
 *
 * The expert view, behind a disclosure. What it shows that the bar chart cannot
 * is WHERE in the round the leak is: the winning curve spikes at a handful of
 * samples and sits in the noise everywhere else.
 */
export function drawCurves(canvas: HTMLCanvasElement, report: DcaReport): string {
  const curves = report.curves;
  if (!curves) {
    sized(canvas, 320, 60);
    return 'No curves were computed for this run.';
  }
  const samples = report.sampleCount;
  const height = 220;
  const ctx = sized(canvas, samples, height);
  const scale = curves.max > 0 ? (height - 20) / curves.max : 0;
  const winner = report.bytes[curves.byteIndex].guess;

  ctx.lineWidth = 1;
  ctx.strokeStyle = FAINT;
  for (let g = 0; g < 256; g++) {
    if (g === winner) continue;
    ctx.beginPath();
    for (let s = 0; s < samples; s++) {
      const y = height - 10 - curves.values[g * samples + s] * scale;
      if (s === 0) ctx.moveTo(0, y);
      else ctx.lineTo(s, y);
    }
    ctx.stroke();
  }
  ctx.strokeStyle = ACCENT;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  for (let s = 0; s < samples; s++) {
    const y = height - 10 - curves.values[winner * samples + s] * scale;
    if (s === 0) ctx.moveTo(0, y);
    else ctx.lineTo(s, y);
  }
  ctx.stroke();

  return (
    `Difference-of-means curves across ${samples} trace samples for key byte ${curves.byteIndex}, ` +
    `one faint curve per wrong candidate and the winning candidate ` +
    `0x${winner.toString(16).padStart(2, '0')} drawn over them. ` +
    `The vertical scale runs to ${curves.max.toFixed(4)}. ` +
    `Predicted from the ${curves.target} target, bit ${curves.bit}. ` +
    'The winning curve sits in the same noise as the others almost everywhere and spikes at the few samples where the encoded nibble it correlates with is being written.'
  );
}
