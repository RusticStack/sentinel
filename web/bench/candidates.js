// U01 log-view candidates, loaded into one page each by log-view.mjs.
// Every candidate ingests the same frames (32 KiB chunks of 127-character
// lines, the shape the API serves) and shows them in a 70vh viewport:
//
//   naive    — one element per line, the first page's approach.
//   preact   — Preact 10 + htm (the smallest mainstream component stack),
//              windowed: only the rows in view are rendered, by state.
//   vue      — Vue 3 (the interface's own framework), windowed the same
//              way: rows rendered reactively from a scroll position.
//   sentinel — the shipped viewer (web/app/utils/logviewer.ts, bundled
//              by log-view.mjs) with its API replaced by the same frames.
//
// Each sets `window.bench = { load(frames) -> Promise, viewport }`.

"use strict";

function makeFrames(lines) {
  const frames = [];
  let chunk = "", seq = 0;
  for (let i = 1; i <= lines; i++) {
    const text = `line ${String(i).padStart(9)} of the flood: the quick brown fox jumps over the lazy dog`;
    const line = text + ".".repeat(127 - text.length) + "\n";
    if (chunk.length + line.length > 32768) { frames.push({ seq: ++seq, step: 0, stream: "stdout", text: chunk }); chunk = ""; }
    chunk += line;
  }
  if (chunk) frames.push({ seq: ++seq, step: 0, stream: "stdout", text: chunk });
  return frames;
}
window.makeFrames = makeFrames;

const LINE_H = 18;

// ------------------------------------------------------------- naive ----
function naiveCandidate(root) {
  const view = document.createElement("pre");
  view.className = "log-view";
  view.style.cssText = "margin:0;white-space:pre";
  root.append(view);
  return {
    viewport: view,
    async load(frames) {
      for (const f of frames) {
        const fragment = document.createDocumentFragment();
        for (const line of f.text.split("\n")) {
          if (!line) continue;
          const div = document.createElement("div");
          div.textContent = line;
          fragment.append(div);
        }
        view.append(fragment);
      }
      void view.scrollHeight; // lay it out
    },
  };
}

// ------------------------------------------------------------ preact ----
function preactCandidate(root) {
  const { h, render } = window.preact;
  const { useState, useEffect, useRef } = window.preactHooks;
  const html = window.htm.bind(h);
  const store = { lines: [], listeners: [] };
  let viewportEl = null;
  function LogView() {
    const [top, setTop] = useState(0);
    const [count, setCount] = useState(0);
    const ref = useRef(null);
    useEffect(() => { store.listeners.push(setCount); viewportEl = ref.current; }, []);
    const height = 0.7 * window.innerHeight;
    const first = Math.max(0, Math.floor(top / LINE_H) - 12);
    const last = Math.min(count, Math.ceil((top + height) / LINE_H) + 12);
    const rows = [];
    for (let i = first; i < last; i++) {
      rows.push(html`<div key=${i} class="log-row" role="listitem" style=${`transform:translateY(${i * LINE_H}px)`}>
        <a class="gut" href=${`#l${i + 1}`}>${i + 1}</a><span class="txt">${store.lines[i]}</span></div>`);
    }
    return html`<div ref=${ref} class="log-view" role="list" tabindex="0" onScroll=${(e) => setTop(e.currentTarget.scrollTop)}>
      <div class="log-spacer" style=${`height:${count * LINE_H}px`}></div>${rows}</div>`;
  }
  render(h(LogView), root);
  return {
    get viewport() { return viewportEl; },
    async load(frames) {
      for (const f of frames) for (const line of f.text.split("\n")) if (line) store.lines.push(line);
      for (const set of store.listeners) set(store.lines.length);
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    },
  };
}

// --------------------------------------------------------------- vue ----
function vueCandidate(root) {
  const { createApp, h, ref, shallowRef, onMounted } = window.Vue;
  const lines = shallowRef([]);
  const top = ref(0);
  let viewportEl = null;
  const app = createApp({
    setup() {
      const el = ref(null);
      onMounted(() => { viewportEl = el.value; });
      return () => {
        const height = 0.7 * window.innerHeight;
        const count = lines.value.length;
        const first = Math.max(0, Math.floor(top.value / LINE_H) - 12);
        const last = Math.min(count, Math.ceil((top.value + height) / LINE_H) + 12);
        const rows = [];
        for (let i = first; i < last; i++) {
          rows.push(h("div", { key: i, class: "log-row", role: "listitem", style: { transform: `translateY(${i * LINE_H}px)` } }, [
            h("a", { class: "gut", href: `#l${i + 1}` }, String(i + 1)), h("span", { class: "txt" }, lines.value[i])]));
        }
        return h("div", { ref: el, class: "log-view", role: "list", tabindex: "0", onScroll: (e) => { top.value = e.currentTarget.scrollTop; } },
          [h("div", { class: "log-spacer", style: { height: `${count * LINE_H}px` } }), ...rows]);
      };
    },
  });
  app.mount(root);
  return {
    get viewport() { return viewportEl; },
    async load(frames) {
      const all = [];
      for (const f of frames) for (const line of f.text.split("\n")) if (line) all.push(line);
      lines.value = all;
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    },
  };
}

// ---------------------------------------------------------- sentinel ----
function sentinelCandidate(root) {
  let frames = [];
  // The viewer's API, answered from memory with the API's page bounds
  // (at most 500 frames and 1 MiB of payload).
  const page = async (query) => {
    const after = Number(new URLSearchParams(query).get("after") || 0);
    const out = [];
    let bytes = 0, i = after;
    while (i < frames.length && out.length < 500 && bytes + frames[i].text.length <= 1 << 20) { bytes += frames[i].text.length; out.push(frames[i]); i++; }
    const more = i < frames.length;
    return { frames: out, complete: true, gaps: [], next_after: more ? i : null, step_done: !more };
  };
  const holder = document.createElement("div");
  root.append(holder);
  let viewer = null;
  return {
    get viewport() { return viewer.viewport; },
    async load(all) {
      frames = all;
      viewer = new window.SentinelLog.LogViewer(holder, {
        attempt: "att_bench", run: "run_bench", steps: [{ index: 0, id: "flood" }], complete: true,
        outcomes: [{ index: 0, id: "flood", outcome: "failed" }],
        page, search: async () => ({ matches: [], next_after: null, next_carry: null, complete: true }),
        announce: () => {}, refused: () => {}, linked: () => {},
      });
      const sec = viewer.sections[0];
      while (!sec.done) await viewer.loadPage(sec);
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    },
  };
}

window.candidates = { naive: naiveCandidate, preact: preactCandidate, vue: vueCandidate, sentinel: sentinelCandidate };
