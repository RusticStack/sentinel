// The log viewer (U03): one attempt's log as steps that fold, each loaded on
// demand through `?step=` pages; a live attempt is followed through this
// server's event stream, resumed after the last frame held. Only the rows in
// view (plus a small overscan) exist as elements, whatever the log's
// length; lines held in memory are bounded, and what the bound released,
// what the store never stored (gaps) and a line cut short are always said.
//
// Plain DOM on purpose, outside Vue's reactivity: up to a quarter-million
// held lines, their typed columns, the memory bound and the stream state
// are ordinary data here, never proxied or tracked. The pooled rows are
// reused and only their text, link and class change while scrolling;
// U01 (docs/web-ui.md, bench/u01-log-view.jsonl) measured this within
// noise of the same window rendered by Vue or Preact.

import type { Frame, LogPage, StepRecord } from "~~/shared/types/api";
import { fmtNs } from "./format";

export const LOG = {
  PAGE_FRAMES: 500,     // the API's page ceiling
  OVERSCAN: 12,         // rows rendered above and below the viewport
  MAX_LINES: 250000,    // lines held across all steps
  MAX_CHARS: 48 << 20,  // characters held across all steps
  TRIM: 25000,          // lines released at once when a bound is hit
  MAX_LINE: 4096,       // characters of one line shown before "… N more"
  JUMP_CONTEXT: 40,     // frames loaded before a deep-linked line
  LINE_H: 18,
};

// ANSI CSI/OSC sequences are dropped: colour codes are noise in text.
const ANSI = /\x1b\[[0-?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]/g;
const STREAM = { stdout: 0, stderr: 1, meta: 2 } as const;

type Kind = Float64ArrayConstructor | Uint8ArrayConstructor;
/// Growable typed columns: no object per line.
class Column {
  private data: Float64Array | Uint8Array;
  length = 0;
  constructor(private kind: Kind) { this.data = new kind(1024); }
  push(v: number) {
    if (this.length === this.data.length) {
      const next = new this.kind(this.data.length * 2);
      next.set(this.data);
      this.data = next;
    }
    this.data[this.length++] = v;
  }
  get(i: number): number { return this.data[i]!; }
  drop(n: number) { this.data.copyWithin(0, n, this.length); this.length -= n; }
}

function el(tag: string, attrs: Record<string, any> | null, ...children: (Node | string | null | false | undefined)[]) {
  const node = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "class") node.className = v;
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) node.append(c);
  return node;
}

export class Section {
  index: number;
  id: string;
  outcome: string | null = null;
  duration: number | null = null;
  expanded = false;
  gen = 0;
  text: string[] = [];
  seq = new Column(Float64Array);
  stream = new Column(Uint8Array);
  number = new Column(Float64Array);
  counted = 0;
  chars = 0;
  after = 0;
  fromStart = true;
  dropped = 0;
  done = false;
  open: [boolean, boolean] = [false, false];
  loading = false;
  error: string | null = null;
  constructor(index: number, id: string) { this.index = index; this.id = id; this.reset(0); }
  reset(after: number) {
    // A page requested before a reset belongs to the old window and is
    // dropped when it arrives.
    this.gen++;
    this.text = [];
    this.seq = new Column(Float64Array);
    this.stream = new Column(Uint8Array);
    this.number = new Column(Float64Array);
    this.counted = 0;
    this.chars = 0;
    this.after = after;
    this.fromStart = after === 0;
    this.dropped = 0;
    this.done = false;
    this.open = [false, false];
    this.loading = false;
    this.error = null;
  }
  get lines() { return this.text.length; }
}

export interface ViewerOptions {
  attempt: string;
  run: string;
  steps: { index: number; id: string }[];
  outcomes: StepRecord[] | null;
  complete: boolean;
  /// Read a page of the log (`GET /api/v1/attempts/{id}/logs?…`).
  page: (query: string) => Promise<LogPage>;
  /// Search (`GET …/logs/search?…`).
  search: (query: string) => Promise<{ matches: { seq: number; step: number; text: string }[]; next_after: number | null; next_carry: string | null; complete: boolean }>;
  announce: (text: string) => void;
  /// A refusal (removed from the tenant, session ended).
  refused: (body: any) => void;
  /// Put a deep link into the address bar without navigating.
  linked: (step: number, seq: number, q?: string) => void;
}

export class LogViewer {
  el: HTMLElement;
  o: ViewerOptions;
  sections: Section[];
  live: boolean;
  follow: boolean;
  gaps: [number, number][] = [];
  needle = "";
  highlight = -1;
  starts: number[] = [];
  total = 0;
  pool: HTMLElement[] = [];
  pending = false;
  version = 0;
  shift = 0;
  source: EventSource | null = null;
  closed = false;
  searchFound = 0;
  // Elements.
  results!: HTMLUListElement;
  stateLine!: HTMLElement;
  searchBox!: HTMLInputElement;
  followBox!: HTMLInputElement;
  stepList!: HTMLUListElement;
  spacer!: HTMLElement;
  viewport!: HTMLElement;
  private resize?: ResizeObserver;

  constructor(host: HTMLElement, opts: ViewerOptions) {
    this.el = host;
    this.o = opts;
    this.live = !opts.complete;
    this.follow = this.live;
    this.sections = opts.steps.map((s) => new Section(s.index, s.id));
    for (const record of opts.outcomes || []) {
      const sec = this.section(record.index);
      if (sec) { sec.outcome = record.outcome; sec.duration = record.duration_ns ?? null; }
    }
    this.build();
    this.foldDefaults();
    this.renderSteps();
    this.layout();
    (host as any).logViewer = this;
  }

  destroy() {
    this.closed = true;
    this.source?.close();
    this.resize?.disconnect();
  }

  section(index: number) { return this.sections.find((s) => s.index === index); }

  build() {
    this.results = el("ul", { class: "max-h-[30vh] overflow-auto rounded-md border border-default divide-y divide-default text-xs font-mono", hidden: true, "aria-label": "Search results" }) as HTMLUListElement;
    this.stateLine = el("p", { class: "text-sm text-muted min-h-5", role: "status", "aria-live": "polite" });
    this.searchBox = el("input", { id: "log-q", type: "search", maxlength: "256", placeholder: "Search this log (literal text)", autocomplete: "off",
      class: "rounded-md border border-default bg-default px-2.5 py-1.5 text-sm w-72 max-w-full" }) as HTMLInputElement;
    this.followBox = el("input", { id: "log-follow", type: "checkbox", checked: this.follow, disabled: !this.live,
      onchange: () => { this.follow = this.followBox.checked; if (this.follow) this.scrollToEnd(); } }) as HTMLInputElement;
    this.stepList = el("ul", { class: "rounded-md border border-default divide-y divide-default overflow-auto max-h-[30vh] lg:max-h-[70vh]", "aria-label": "Steps" }) as HTMLUListElement;
    this.spacer = el("div", { class: "log-spacer" });
    this.viewport = el("div", { id: "log-view", class: "log-view", tabindex: "0", role: "list", "aria-label": "Log lines", "aria-describedby": "log-keys" }, this.spacer);
    this.viewport.addEventListener("scroll", () => this.schedule(), { passive: true });
    this.viewport.addEventListener("keydown", (e) => this.keys(e));
    this.resize = new ResizeObserver(() => this.schedule());
    this.resize.observe(this.viewport);
    const button = (label: string, onclick: () => void, primary = false) =>
      el("button", { type: primary ? "submit" : "button", class: `rounded-md px-2.5 py-1.5 text-sm font-medium ${primary ? "bg-primary text-inverted" : "bg-elevated text-default ring ring-inset ring-accented"}`, onclick: primary ? null : onclick }, label);
    const form = el("form", { class: "flex flex-wrap items-center gap-2 mb-2", role: "search", onsubmit: (e: Event) => { e.preventDefault(); this.runSearch(); } },
      el("label", { for: "log-q", class: "sr" }, "Search this log"), this.searchBox,
      button("Find", () => {}, true), button("Clear", () => this.clearSearch()),
      el("label", { class: "flex items-center gap-1.5 text-sm ml-2" }, this.followBox, "Follow live output"),
      button("Expand all", () => this.setAll(true)), button("Fold all", () => this.setAll(false)));
    this.el.replaceChildren(el("div", { class: "grid gap-3 lg:grid-cols-[minmax(12rem,15rem)_1fr]" },
      el("nav", { "aria-label": "Steps" }, this.stepList),
      el("div", { class: "min-w-0" }, form, this.results, this.stateLine,
        el("p", { id: "log-keys", class: "sr" }, "Arrow keys scroll by line, Page Up and Page Down by screen, Home and End jump to the ends."),
        this.viewport)));
  }

  /// Failed and unfinished steps open; passed or skipped ones fold. With
  /// no outcomes yet, the last step (the one being written) opens.
  foldDefaults() {
    let any = false;
    for (const s of this.sections) {
      s.expanded = s.outcome !== null && !["passed", "skipped", "not_run"].includes(s.outcome);
      any = any || s.expanded;
    }
    if (!any && this.sections.length && (this.live || !this.sections.some((s) => s.outcome))) {
      this.sections[this.sections.length - 1]!.expanded = true;
    }
  }

  renderSteps() {
    this.stepList.replaceChildren(...this.sections.map((s) => el("li", null,
      el("button", { type: "button", "aria-expanded": String(s.expanded), "aria-controls": "log-view",
        class: "w-full text-left px-2.5 py-1.5 grid grid-cols-[1fr_auto] gap-x-2 text-sm hover:bg-elevated focus-visible:outline-2 focus-visible:outline-primary",
        onclick: () => this.toggle(s, true) },
      el("span", { class: "font-medium truncate" }, s.id || `step ${s.index}`),
      el("span", { class: s.outcome === "passed" ? "text-success" : s.outcome ? "text-error" : "text-muted" }, s.outcome ? s.outcome.replace(/_/g, " ") : this.live ? "…" : ""),
      el("span", { class: "text-xs text-muted" }, s.duration ? fmtNs(s.duration) : ""),
      el("span", { class: "text-xs text-muted", "data-count": "" }, s.expanded ? `${s.lines.toLocaleString()} lines` : "folded")))));
  }

  layout() {
    let row = 0;
    this.starts = this.sections.map((s) => {
      const start = row;
      row += 1 + (s.expanded ? (s.fromStart ? 0 : 1) + s.lines + 1 : 0);
      return start;
    });
    this.total = row;
    this.spacer.style.height = `${this.total * LOG.LINE_H}px`;
    if (this.shift) { this.viewport.scrollTop = Math.max(0, this.viewport.scrollTop - this.shift * LOG.LINE_H); this.shift = 0; }
    this.changed();
  }

  changed() { this.version++; this.schedule(); }

  locate(row: number): [Section, number] {
    let lo = 0, hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid]! <= row) lo = mid; else hi = mid - 1;
    }
    return [this.sections[lo]!, row - this.starts[lo]!];
  }

  schedule() {
    if (this.pending || this.closed) return;
    this.pending = true;
    requestAnimationFrame(() => { this.pending = false; this.paint(); });
  }

  paint() {
    const top = this.viewport.scrollTop;
    const height = this.viewport.clientHeight || 400;
    const first = Math.max(0, Math.floor(top / LOG.LINE_H) - LOG.OVERSCAN);
    const last = Math.min(this.total, Math.ceil((top + height) / LOG.LINE_H) + LOG.OVERSCAN);
    const count = Math.max(0, last - first);
    while (this.pool.length < count) {
      const row = el("div", { class: "log-row", role: "listitem" });
      this.viewport.append(row);
      this.pool.push(row);
    }
    for (let i = 0; i < this.pool.length; i++) {
      const row = this.pool[i]!;
      if (i >= count) { if (!row.hidden) row.hidden = true; continue; }
      if (row.hidden) row.hidden = false;
      this.draw(row, first + i);
    }
    this.maybeLoad(first, last);
  }

  draw(row: HTMLElement & { shownRow?: number; shownVersion?: number; shownTotal?: number; parts?: HTMLElement[] | null }, index: number) {
    // A pooled row already showing this row at this version is left
    // alone: scrolling redraws only the rows that came into view.
    if (row.shownRow === index && row.shownVersion === this.version) return;
    row.shownRow = index;
    row.shownVersion = this.version;
    row.style.transform = `translateY(${index * LOG.LINE_H}px)`;
    row.setAttribute("aria-posinset", String(index + 1));
    if (row.shownTotal !== this.total) { row.shownTotal = this.total; row.setAttribute("aria-setsize", String(this.total)); }
    const [sec, local] = this.locate(index);
    const offset = sec.fromStart ? 0 : 1;
    const i = local - 1 - offset;
    if (local > offset && i < sec.lines) return this.drawLine(row, index, sec, i);
    row.className = index === this.highlight ? "log-row hl" : "log-row";
    row.replaceChildren();
    row.parts = null;
    if (local === 0) {
      row.classList.add("head");
      row.append(el("button", { type: "button", "aria-expanded": String(sec.expanded), onclick: () => this.toggle(sec, false) },
        el("span", { "aria-hidden": "true" }, sec.expanded ? "▾" : "▸"),
        el("span", null, sec.id || `step ${sec.index}`),
        sec.outcome ? el("span", null, sec.outcome.replace(/_/g, " ")) : null,
        sec.duration ? el("span", { class: "muted" }, fmtNs(sec.duration)) : null,
        el("span", { class: "muted" }, sec.expanded ? `${sec.lines.toLocaleString()} lines held` : "folded")));
      return;
    }
    row.classList.add("meta");
    if (local === 1 && !sec.fromStart) {
      row.append(el("span", { class: "gut" }, ""), el("span", { class: "txt" },
        sec.dropped ? `… ${sec.dropped.toLocaleString()} earlier lines released to bound memory — ` : "… earlier lines not loaded — ",
        el("button", { type: "button", class: "link", onclick: () => this.loadEarlier(sec) }, "load earlier")));
      return;
    }
    const text = sec.error ? `Could not load: ${sec.error}` : sec.loading ? "Loading…"
      : sec.done ? (sec.lines ? "End of step." : "This step printed nothing.")
        : this.live ? "Waiting for output…" : "More below — scroll to load.";
    row.append(el("span", { class: "gut" }, ""), el("span", { class: "txt" }, text));
  }

  /// The common row keeps its two nodes (link and text); only their text,
  /// the link and the class move. Only a stderr row carries a third, the
  /// "stderr:" said to screen readers, so ordinary rows cost no more.
  drawLine(row: HTMLElement & { parts?: HTMLElement[] | null; sr?: HTMLElement; cls?: string }, index: number, sec: Section, i: number) {
    const stream = sec.stream.get(i);
    const seq = sec.seq.get(i);
    const number = sec.number.get(i) || 0;
    let parts = row.parts;
    if (!parts || row.firstChild !== parts[0]) {
      parts = row.parts = [el("a", { class: "gut" }), el("span", { class: "txt" })];
      row.replaceChildren(...parts);
      row.cls = undefined;
    }
    const [gut, txt] = parts as [HTMLAnchorElement, HTMLElement];
    let cls = stream === STREAM.stderr ? "log-row err" : stream === STREAM.meta ? "log-row meta" : "log-row";
    if (index === this.highlight) cls += " hl";
    if (row.cls !== cls) { row.className = cls; row.cls = cls; }
    gut.href = this.link(sec.index, seq);
    gut.textContent = number ? String(number) : "·";
    if (!number) gut.setAttribute("aria-label", `Link to frame ${seq}`);
    else if (gut.hasAttribute("aria-label")) gut.removeAttribute("aria-label");
    if (stream === STREAM.stderr) {
      if (!row.sr) row.sr = el("span", { class: "sr" }, "stderr: ");
      if (row.sr.parentNode !== row) row.insertBefore(row.sr, txt);
    } else if (row.sr?.parentNode === row) row.sr.remove();
    const text = sec.text[i]!;
    if (!this.needle && text.length <= LOG.MAX_LINE) txt.textContent = text;
    else { txt.replaceChildren(); this.fill(txt, text); }
  }

  fill(node: HTMLElement, text: string) {
    let shown = text, more = 0;
    if (text.length > LOG.MAX_LINE) { shown = text.slice(0, LOG.MAX_LINE); more = text.length - LOG.MAX_LINE; }
    if (this.needle) {
      let at = 0, hit;
      while ((hit = shown.indexOf(this.needle, at)) >= 0) {
        node.append(shown.slice(at, hit), el("mark", null, this.needle));
        at = hit + this.needle.length;
      }
      node.append(shown.slice(at));
    } else node.append(shown);
    if (more) node.append(el("span", { class: "muted" }, ` … ${more.toLocaleString()} more characters`));
  }

  link(step: number, seq: number) {
    return `/runs/${this.o.run}/logs/${this.o.attempt}?step=${step}&seq=${seq}`;
  }

  keys(e: KeyboardEvent) {
    const vp = this.viewport, page = vp.clientHeight - LOG.LINE_H;
    const moves: Record<string, number> = { ArrowDown: LOG.LINE_H, ArrowUp: -LOG.LINE_H, PageDown: page, PageUp: -page };
    if (e.key in moves) vp.scrollTop += moves[e.key]!;
    else if (e.key === "Home") vp.scrollTop = 0;
    else if (e.key === "End") vp.scrollTop = vp.scrollHeight;
    else return;
    e.preventDefault();
    if (e.key !== "End") { this.follow = false; this.followBox.checked = false; }
  }

  toggle(sec: Section, fromList: boolean) {
    sec.expanded = !sec.expanded;
    this.renderSteps();
    this.layout();
    if (fromList && sec.expanded) this.viewport.scrollTop = this.starts[this.sections.indexOf(sec)]! * LOG.LINE_H;
    this.o.announce(`${sec.id || "step " + sec.index} ${sec.expanded ? "expanded" : "folded"}`);
  }

  setAll(open: boolean) {
    for (const s of this.sections) s.expanded = open;
    this.renderSteps();
    this.layout();
  }

  maybeLoad(first: number, last: number) {
    if (this.live) return; // the stream fills a live log
    for (let k = 0; k < this.sections.length; k++) {
      const sec = this.sections[k]!;
      if (!sec.expanded || sec.loading || sec.done || sec.error) continue;
      const endRow = this.starts[k]! + 1 + (sec.fromStart ? 0 : 1) + sec.lines;
      if (endRow >= first && endRow <= last + 200) this.loadPage(sec).catch(() => {});
    }
  }

  /// One page of a step past `sec.after`.
  async loadPage(sec: Section): Promise<LogPage | null> {
    const gen = sec.gen;
    sec.loading = true;
    this.changed();
    try {
      const page = await this.o.page(`step=${sec.index}&after=${sec.after}&limit=${LOG.PAGE_FRAMES}`);
      if (gen !== sec.gen) return null;
      this.gaps = page.gaps || this.gaps;
      this.appendFrames(sec, page.frames);
      if (page.next_after !== null && page.next_after !== undefined) sec.after = Math.max(sec.after, page.next_after);
      if (page.next_after === null && (page.step_done || page.complete)) sec.done = true;
      sec.error = null;
      return page;
    } catch (e: any) {
      if (gen === sec.gen) {
        sec.error = e?.message || "failed";
        if (e?.code === "not_found" || e?.code === "forbidden") { sec.done = true; this.o.refused(e); }
      }
      return null;
    } finally {
      if (gen === sec.gen) sec.loading = false;
      this.layout();
      this.renderStepCount(sec);
    }
  }

  renderStepCount(sec: Section) {
    const item = this.stepList.children[this.sections.indexOf(sec)];
    const count = item?.querySelector("[data-count]");
    if (count) count.textContent = sec.expanded ? `${sec.lines.toLocaleString()} lines` : "folded";
  }

  /// Frames into lines; an open line continues in the same stream's next
  /// frame. A jump over a declared gap becomes a visible marker line.
  appendFrames(sec: Section, frames: Frame[]) {
    for (const f of frames) {
      if (f.seq <= sec.after && sec.lines) continue; // already held
      const last = sec.lines ? sec.seq.get(sec.lines - 1) : sec.after;
      for (const [from, to] of this.gaps) {
        if (from > last && to < f.seq) {
          this.pushLine(sec, from === to ? `[frame ${from} was never stored: the log has a gap here]` : `[frames ${from}–${to} were never stored: the log has a gap here]`, STREAM.meta, from);
        }
      }
      const stream = f.stream === "stderr" ? STREAM.stderr : STREAM.stdout;
      // The escape byte is rare; only a frame holding one pays for the regex.
      const parts = (f.text.indexOf("\x1b") < 0 ? f.text : f.text.replace(ANSI, "")).split("\n");
      for (let p = 0; p < parts.length; p++) {
        const piece = parts[p]!;
        const endsLine = p < parts.length - 1;
        if (p === parts.length - 1 && piece === "") break;
        if (p === 0 && sec.open[stream] && sec.lines) {
          const i = this.lastOf(sec, stream);
          if (i >= 0) { sec.chars += piece.length; sec.text[i] += piece; sec.open[stream] = !endsLine; continue; }
        }
        this.pushLine(sec, piece, stream, f.seq);
        sec.open[stream] = !endsLine;
      }
      if (parts[parts.length - 1] === "") sec.open[stream] = false;
      sec.after = Math.max(sec.after, f.seq);
    }
    this.bound(sec);
  }

  lastOf(sec: Section, stream: number) {
    for (let i = sec.lines - 1, n = 0; i >= 0 && n < 64; i--, n++) if (sec.stream.get(i) === stream) return i;
    return -1;
  }

  pushLine(sec: Section, text: string, stream: number, seq: number) {
    sec.text.push(text);
    sec.seq.push(seq);
    sec.stream.push(stream);
    sec.number.push(stream !== STREAM.meta && (sec.fromStart || sec.dropped) ? ++sec.counted : 0);
    sec.chars += text.length;
  }

  /// Hold at most MAX_LINES / MAX_CHARS: release the oldest lines of the
  /// largest step, keep what is being read in view, and say so.
  bound(growing: Section) {
    let lines = 0, chars = 0;
    for (const s of this.sections) { lines += s.lines; chars += s.chars; }
    while (lines > LOG.MAX_LINES || chars > LOG.MAX_CHARS) {
      const victim = this.sections.reduce((a, b) => (b.lines > a.lines ? b : a), growing);
      const n = Math.min(LOG.TRIM, victim.lines - 1);
      if (n <= 0) break;
      const k = this.sections.indexOf(victim);
      const firstLine = (this.starts[k] ?? 0) + 1 + (victim.fromStart ? 0 : 1);
      const top = Math.floor(this.viewport.scrollTop / LOG.LINE_H);
      if (victim.expanded && top > firstLine) this.shift += Math.min(n, top - firstLine) - (victim.fromStart ? 1 : 0);
      let released = 0;
      for (let i = 0; i < n; i++) released += victim.text[i]!.length;
      victim.text.splice(0, n);
      victim.seq.drop(n);
      victim.stream.drop(n);
      victim.number.drop(n);
      victim.chars -= released;
      victim.dropped += n;
      victim.fromStart = false;
      lines -= n;
      chars -= released;
      this.highlight = -1;
    }
  }

  async loadEarlier(sec: Section) {
    const first = sec.lines ? sec.seq.get(0) : sec.after;
    await this.window(sec, Math.max(0, first - 1 - LOG.JUMP_CONTEXT * 4), first);
  }

  /// Replace a section with the window after `after`, up to `until`.
  async window(sec: Section, after: number, until: number) {
    sec.reset(after);
    sec.expanded = true;
    this.renderSteps();
    this.layout();
    while (!sec.done && !sec.error && (sec.lines === 0 || sec.seq.get(sec.lines - 1) < until)) {
      const before = sec.after;
      const page = await this.loadPage(sec);
      if (!page || (sec.after === before && !page.frames.length)) break;
    }
  }

  /// Show frame `seq` of step `step` (the line holding `needle`, when
  /// given), highlighted, loading a window around it when not held.
  async jump(step: number, seq: number, needle?: string | null) {
    if (needle) { this.needle = needle; this.searchBox.value = needle; }
    const sec = this.section(step);
    if (!sec) return;
    this.follow = false;
    this.followBox.checked = false;
    let i = this.find(sec, seq, needle);
    if (i < 0) {
      await this.window(sec, Math.max(0, seq - 1 - LOG.JUMP_CONTEXT), seq);
      i = this.find(sec, seq, needle);
    }
    if (!sec.expanded) { sec.expanded = true; this.renderSteps(); this.layout(); }
    if (i < 0) { this.o.announce("That line is not in the stored log."); return; }
    const row = this.starts[this.sections.indexOf(sec)]! + 1 + (sec.fromStart ? 0 : 1) + i;
    this.highlight = row;
    this.viewport.scrollTop = Math.max(0, row * LOG.LINE_H - this.viewport.clientHeight / 3);
    this.changed();
    this.viewport.focus({ preventScroll: true });
    this.o.announce(`Showing ${sec.id || "step " + sec.index}, frame ${seq}.`);
  }

  find(sec: Section, seq: number, needle?: string | null) {
    let lo = 0, hi = sec.lines - 1, found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1, v = sec.seq.get(mid);
      if (v >= seq) { if (v === seq) found = mid; hi = mid - 1; } else lo = mid + 1;
    }
    if (found >= 0 && needle) {
      for (let i = found; i < sec.lines && sec.seq.get(i) === seq; i++) if (sec.text[i]!.includes(needle)) return i;
    }
    return found;
  }

  scrollToEnd() { this.viewport.scrollTop = this.viewport.scrollHeight; }

  /// Follow a live attempt through this server's event stream: frames as
  /// they land, step by step, until the log completes. The browser
  /// reconnects by itself with the last event's `step:seq`, so a dropped
  /// connection never repeats or loses a line.
  followLive() {
    let k = 0;
    while (k < this.sections.length - 1 && this.sections[k]!.outcome) k++;
    const start = this.sections[k];
    if (!start) return;
    start.expanded = true;
    this.renderSteps();
    this.layout();
    const source = new EventSource(`/_stream/log/${this.o.attempt}?step=${start.index}&after=${start.after}`);
    this.source = source;
    let lost = false;
    source.addEventListener("frames", (e) => {
      const { step, frames, gaps } = JSON.parse((e as MessageEvent).data);
      const sec = this.section(step);
      if (!sec) return;
      if (!sec.expanded) { sec.expanded = true; this.renderSteps(); }
      this.gaps = gaps || this.gaps;
      this.appendFrames(sec, frames);
      this.layout();
      this.renderStepCount(sec);
      if (this.follow) this.scrollToEnd();
    });
    source.addEventListener("step_done", (e) => {
      const { step } = JSON.parse((e as MessageEvent).data);
      const sec = this.section(step);
      if (sec) sec.done = true;
      const next = this.sections[this.sections.findIndex((s) => s.index === step) + 1];
      if (next) { next.expanded = true; this.stateLine.textContent = `Following ${next.id || "step " + next.index}.`; this.renderSteps(); }
      this.layout();
    });
    source.addEventListener("complete", (e) => {
      source.close();
      this.live = false;
      // Every step was streamed from its start: all of it is held.
      for (const s of this.sections) s.done = true;
      this.completed(JSON.parse((e as MessageEvent).data));
      this.layout();
    });
    source.addEventListener("status", (e) => {
      const state = (e as MessageEvent).data;
      this.stateLine.textContent = state === "busy" ? "The controller is busy; updates resume by themselves."
        : state === "reconnecting" ? "The controller is unreachable; retrying." : "Live.";
    });
    source.addEventListener("refused", (e) => {
      source.close();
      this.live = false;
      this.o.refused(JSON.parse((e as MessageEvent).data));
    });
    source.onerror = () => {
      if (source.readyState === EventSource.CLOSED) return;
      lost = true;
      this.stateLine.textContent = "Connection lost; reconnecting. Nothing already shown will repeat.";
    };
    source.onopen = () => { if (lost) { lost = false; this.stateLine.textContent = "Live."; } };
  }

  completed(end: { gaps?: [number, number][] }) {
    const gaps = (end.gaps || []).length;
    this.stateLine.textContent = gaps
      ? `The log is complete but has ${gaps} gap${gaps > 1 ? "s" : ""}: some output was never stored.`
      : "The log is complete.";
    this.followBox.checked = false;
    this.followBox.disabled = true;
  }

  clearSearch() {
    this.needle = "";
    this.searchBox.value = "";
    this.results.hidden = true;
    this.results.replaceChildren();
    this.changed();
  }

  /// Indexed literal search on the controller, page by page (4 MiB of log
  /// a request) until something is found; each hit jumps to its line.
  async runSearch(resume?: { after: number; carry: string | null }) {
    const q = this.searchBox.value;
    if (!q) return this.clearSearch();
    this.needle = q;
    if (!resume) { this.results.replaceChildren(); this.searchFound = 0; }
    this.results.hidden = false;
    this.changed();
    let after = resume ? resume.after : 0, carry = resume ? resume.carry : null;
    this.results.querySelector(".more")?.remove();
    for (let pages = 0; pages < 64; pages++) {
      const found = await this.o.search(`q=${encodeURIComponent(q)}&after=${after}&limit=200${carry ? "&carry=" + carry : ""}`);
      for (const m of found.matches) {
        this.searchFound++;
        const step = this.section(m.step);
        this.results.append(el("li", null, el("button", { type: "button", class: "w-full text-left px-2 py-1 truncate hover:bg-elevated",
          onclick: () => { this.o.linked(m.step, m.seq, q); this.jump(m.step, m.seq, q); } },
        `${step ? step.id : "step " + m.step} · ${m.text.replace(ANSI, "").trim()}`)));
      }
      if (found.next_after === null || found.next_after === undefined) {
        this.o.announce(`${this.searchFound} matching line${this.searchFound === 1 ? "" : "s"}${found.complete ? "" : " so far (the log is still being written)"}.`);
        return;
      }
      after = found.next_after;
      carry = found.next_carry;
      if (this.searchFound >= 500 || (this.searchFound > 0 && pages >= 7)) break;
    }
    const next = { after, carry };
    this.results.append(el("li", { class: "more" }, el("button", { type: "button", class: "w-full text-left px-2 py-1 text-primary", onclick: () => this.runSearch(next) }, "Search further")));
    this.o.announce(`${this.searchFound} matches shown; more of the log remains to search.`);
  }
}
