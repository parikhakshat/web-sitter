/* global REPORT */
(function () {
  'use strict';

  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_COLORS = {
    critical: '#f85149',
    high: '#f85149',
    medium: '#d29922',
    low: '#58a6ff',
    info: '#3fb950',
  };

  // ── CPG subgraph lazy loader ──────────────────────────────────────────────────

  const _cpgCache = {};
  function getCpgGraph(finding, index) {
    if (index === undefined) return null;
    if (_cpgCache[index] !== undefined) return _cpgCache[index];
    const el = document.getElementById('cpg-' + index);
    const parsed = el ? JSON.parse(el.textContent) : null;
    _cpgCache[index] = parsed;
    return parsed;
  }

  // ── CPG graph renderer ────────────────────────────────────────────────────────

  const graphInstances = {};

  class CpgGraphRenderer {
    constructor(fid, graph, matchedIds, primaryFile) {
      this.fid = fid;
      this.nodes = graph.nodes || [];
      this.edges = graph.edges || [];
      this.matched = new Set(matchedIds || []);
      this.primaryFile = primaryFile;
      this.canvas = document.getElementById(`graph-canvas-${fid}`);
      this.wrap = document.getElementById(`graph-wrap-${fid}`);
      this.tooltip = document.getElementById(`graph-tooltip-${fid}`);
      this.ctx = this.canvas && this.canvas.getContext('2d');
      this.showAst = true;
      this.showDfg = true;
      this.transform = { x: 0, y: 0, scale: 1 };
      this.nodePositions = {};
      this.NODE_W = 170;
      this.NODE_H = 48;
      this.HGAP = 32;
      this.VGAP = 52;
      this.dragging = false;
      this.dragStart = null;
      this.transformStart = null;
      this._bindEvents();
      this.resize();
      this.runLayout();
    }

    _bindEvents() {
      if (!this.canvas) return;
      this.canvas.addEventListener('mousedown', (e) => {
        this.dragging = true;
        this.dragStart = { x: e.clientX, y: e.clientY };
        this.transformStart = { ...this.transform };
        this.canvas.classList.add('dragging');
      });
      this.canvas.addEventListener('mousemove', (e) => {
        if (this.dragging && this.dragStart) {
          this.transform.x = this.transformStart.x + (e.clientX - this.dragStart.x);
          this.transform.y = this.transformStart.y + (e.clientY - this.dragStart.y);
          this.render();
          return;
        }
        const rect = this.canvas.getBoundingClientRect();
        const w = this.canvasToWorld(e.clientX - rect.left, e.clientY - rect.top);
        const n = this.hitNode(w.x, w.y);
        if (n && this.tooltip) {
          this.tooltip.style.display = 'block';
          this.tooltip.style.left = `${e.clientX + 12}px`;
          this.tooltip.style.top = `${e.clientY + 8}px`;
          const textPart = n.x ? `"${n.x.length > 50 ? n.x.slice(0, 49) + '…' : n.x}"` : null;
          this.tooltip.textContent = [n.t, textPart, `line ${n.line}`].filter(Boolean).join('\n');
        } else if (this.tooltip) {
          this.tooltip.style.display = 'none';
        }
      });
      this.canvas.addEventListener('mouseup', (e) => {
        if (!this.dragging) return;
        const dx = e.clientX - (this.dragStart ? this.dragStart.x : 0);
        const dy = e.clientY - (this.dragStart ? this.dragStart.y : 0);
        this.dragging = false;
        this.canvas.classList.remove('dragging');
        if (Math.abs(dx) < 4 && Math.abs(dy) < 4) {
          const rect = this.canvas.getBoundingClientRect();
          const w = this.canvasToWorld(e.clientX - rect.left, e.clientY - rect.top);
          const n = this.hitNode(w.x, w.y);
          const file = (n && n.file) || this.primaryFile;
          if (n && n.line > 0) openSnippet(file, n.line);
        }
      });
      this.canvas.addEventListener('mouseleave', () => {
        this.dragging = false;
        this.canvas.classList.remove('dragging');
        if (this.tooltip) this.tooltip.style.display = 'none';
      });
      this.canvas.addEventListener('wheel', (e) => {
        e.preventDefault();
        const factor = e.deltaY < 0 ? 1.1 : 0.9;
        const rect = this.canvas.getBoundingClientRect();
        const cx = e.clientX - rect.left;
        const cy = e.clientY - rect.top;
        this.transform.x = cx + (this.transform.x - cx) * factor;
        this.transform.y = cy + (this.transform.y - cy) * factor;
        this.transform.scale = Math.min(Math.max(this.transform.scale * factor, 0.1), 5);
        this.render();
      }, { passive: false });
      window.addEventListener('resize', () => this.resize());
    }

    buildChildMap() {
      const cm = {};
      this.nodes.forEach((n) => { cm[n.id] = []; });
      this.edges.filter((e) => e.k === 'A').forEach((e) => {
        if (cm[e.s]) cm[e.s].push(e.d);
      });
      return cm;
    }

    findRoots(childMap) {
      const hasParent = new Set();
      this.edges.filter((e) => e.k === 'A').forEach((e) => hasParent.add(e.d));
      return this.nodes.filter((n) => !hasParent.has(n.id)).map((n) => n.id);
    }

    computeSubtreeWidth(id, childMap, memo) {
      if (memo[id] !== undefined) return memo[id];
      const ch = childMap[id] || [];
      if (!ch.length) { memo[id] = this.NODE_W; return this.NODE_W; }
      const total = ch.reduce((s, c) => s + this.computeSubtreeWidth(c, childMap, memo) + this.HGAP, -this.HGAP);
      memo[id] = Math.max(this.NODE_W, total);
      return memo[id];
    }

    layoutTree(id, x, y, childMap, widthMemo) {
      this.nodePositions[id] = { x, y, w: this.NODE_W, h: this.NODE_H };
      const ch = childMap[id] || [];
      if (!ch.length) return;
      const totalW = ch.reduce((s, c) => s + this.computeSubtreeWidth(c, childMap, widthMemo) + this.HGAP, -this.HGAP);
      let cx = x - totalW / 2;
      ch.forEach((c) => {
        const cw = this.computeSubtreeWidth(c, childMap, widthMemo);
        this.layoutTree(c, cx + cw / 2, y + this.NODE_H + this.VGAP, childMap, widthMemo);
        cx += cw + this.HGAP;
      });
    }

    runLayout() {
      this.nodePositions = {};
      const childMap = this.buildChildMap();
      const widthMemo = {};
      this.nodes.forEach((n) => this.computeSubtreeWidth(n.id, childMap, widthMemo));
      const roots = this.findRoots(childMap);
      const astConnected = new Set();
      this.edges.filter((e) => e.k === 'A').forEach((e) => { astConnected.add(e.s); astConnected.add(e.d); });
      roots.forEach((n) => astConnected.add(n));
      let rootX = 60;
      roots.forEach((r) => {
        const rw = widthMemo[r] || this.NODE_W;
        this.layoutTree(r, rootX + rw / 2, 40, childMap, widthMemo);
        rootX += rw + this.HGAP * 3;
      });
      const orphans = this.nodes.filter((n) => !astConnected.has(n.id));
      let ox = 40;
      const maxY = Math.max(40, ...Object.values(this.nodePositions).map((p) => p.y + p.h));
      orphans.forEach((n) => {
        this.nodePositions[n.id] = { x: ox, y: maxY + this.VGAP * 2, w: this.NODE_W, h: this.NODE_H };
        ox += this.NODE_W + this.HGAP;
      });
      this.centerView();
      this.render();
    }

    resize() {
      if (!this.canvas || !this.wrap) return;
      this.canvas.width = this.wrap.clientWidth || 800;
      this.canvas.height = this.wrap.clientHeight || 500;
      this.render();
    }

    nodeColor(n) {
      if (this.matched.has(n.id)) return { fill: '#ffeaea', stroke: '#f85149', typeText: '#c0392b', bodyText: '#7b1a1a' };
      const t = n.t || '';
      if (t === 'identifier') return { fill: '#eaf4ff', stroke: '#58a6ff', typeText: '#2272b3', bodyText: '#1a3a55' };
      if (t === 'call_expression') return { fill: '#f5eaff', stroke: '#a371f7', typeText: '#7c3aad', bodyText: '#3d1a55' };
      if (t.includes('declaration') || t === 'function_definition') return { fill: '#eafff0', stroke: '#3fb950', typeText: '#2e6e2e', bodyText: '#1a3d1a' };
      return { fill: '#f5f5f5', stroke: '#aaaaaa', typeText: '#555555', bodyText: '#333333' };
    }

    drawArrow(x1, y1, x2, y2, color, dashed) {
      const dx = x2 - x1; const dy = y2 - y1;
      const len = Math.sqrt(dx * dx + dy * dy);
      if (len < 1) return;
      const ux = dx / len; const uy = dy / len;
      const sx = x1 + ux * (this.NODE_W / 2 + 4);
      const sy = y1 + uy * (this.NODE_H / 2 + 4);
      const ex = x2 - ux * (this.NODE_W / 2 + 6);
      const ey = y2 - uy * (this.NODE_H / 2 + 6);
      const ctx = this.ctx;
      ctx.save();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.2;
      if (dashed) ctx.setLineDash([4, 3]);
      ctx.beginPath();
      ctx.moveTo(sx, sy);
      if (dashed) {
        const mx = (sx + ex) / 2 - uy * 20;
        const my = (sy + ey) / 2 + ux * 20;
        ctx.quadraticCurveTo(mx, my, ex, ey);
      } else {
        ctx.lineTo(ex, ey);
      }
      ctx.stroke();
      ctx.setLineDash([]);
      const angle = Math.atan2(ey - sy, ex - sx);
      const arrowSize = 7;
      ctx.beginPath();
      ctx.moveTo(ex, ey);
      ctx.lineTo(ex - arrowSize * Math.cos(angle - 0.4), ey - arrowSize * Math.sin(angle - 0.4));
      ctx.lineTo(ex - arrowSize * Math.cos(angle + 0.4), ey - arrowSize * Math.sin(angle + 0.4));
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();
      ctx.restore();
    }

    render() {
      const ctx = this.ctx;
      if (!ctx) return;
      ctx.save();
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
      ctx.translate(this.transform.x, this.transform.y);
      ctx.scale(this.transform.scale, this.transform.scale);

      this.edges.forEach((e) => {
        if (e.k === 'A' && !this.showAst) return;
        if (e.k === 'D' && !this.showDfg) return;
        const sp = this.nodePositions[e.s];
        const dp = this.nodePositions[e.d];
        if (!sp || !dp) return;
        const color = e.k === 'D' ? '#2196f3' : '#aaaaaa';
        this.drawArrow(
          sp.x + this.NODE_W / 2, sp.y + this.NODE_H / 2,
          dp.x + this.NODE_W / 2, dp.y + this.NODE_H / 2,
          color, e.k === 'D',
        );
        if (e.k === 'D' && e.v) {
          const mx = (sp.x + dp.x) / 2 + this.NODE_W / 2;
          const my = (sp.y + dp.y) / 2 + this.NODE_H / 2;
          ctx.font = '9px monospace';
          ctx.fillStyle = '#1565c0';
          ctx.textAlign = 'center';
          ctx.fillText(String(e.v).slice(0, 16), mx, my - 5);
        }
      });

      this.nodes.forEach((n) => {
        const pos = this.nodePositions[n.id];
        if (!pos) return;
        const col = this.nodeColor(n);
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(pos.x, pos.y, this.NODE_W, this.NODE_H, 5);
        else ctx.rect(pos.x, pos.y, this.NODE_W, this.NODE_H);
        ctx.fillStyle = col.fill;
        ctx.fill();
        ctx.strokeStyle = col.stroke;
        ctx.lineWidth = this.matched.has(n.id) ? 2.5 : 1;
        ctx.stroke();
        const typeLabel = String(n.t || '').replace(/_/g, ' ');
        ctx.font = 'bold 9px monospace';
        ctx.fillStyle = col.typeText;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'alphabetic';
        ctx.fillText(typeLabel.slice(0, 24), pos.x + this.NODE_W / 2, pos.y + 16);
        const bodyRaw = n.x || '';
        const body = bodyRaw.length > 50 ? bodyRaw.slice(0, 49) + '…' : bodyRaw || '—';
        ctx.font = '10px monospace';
        ctx.fillStyle = col.bodyText;
        ctx.fillText(body.slice(0, 22), pos.x + this.NODE_W / 2, pos.y + 30);
        ctx.font = '8px monospace';
        ctx.fillStyle = '#888888';
        ctx.textAlign = 'right';
        ctx.fillText(':' + n.line, pos.x + this.NODE_W - 4, pos.y + this.NODE_H - 3);
      });
      ctx.restore();
    }

    centerView() {
      const positions = Object.values(this.nodePositions);
      if (!positions.length) return;
      const xs = positions.map((p) => p.x);
      const ys = positions.map((p) => p.y);
      const minX = Math.min(...xs);
      const maxX = Math.max(...xs) + this.NODE_W;
      const minY = Math.min(...ys);
      const maxY = Math.max(...ys) + this.NODE_H;
      const W = this.canvas.width || 800;
      const H = this.canvas.height || 500;
      const scaleX = W / (maxX - minX + 80);
      const scaleY = H / (maxY - minY + 80);
      const scale = Math.min(Math.max(Math.min(scaleX, scaleY), 0.25), 1.5);
      this.transform.scale = scale;
      this.transform.x = (W - (maxX + minX) * scale) / 2;
      this.transform.y = (H - (maxY + minY) * scale) / 2;
    }

    canvasToWorld(cx, cy) {
      return {
        x: (cx - this.transform.x) / this.transform.scale,
        y: (cy - this.transform.y) / this.transform.scale,
      };
    }

    hitNode(wx, wy) {
      return this.nodes.find((n) => {
        const p = this.nodePositions[n.id];
        return p && wx >= p.x && wx <= p.x + this.NODE_W && wy >= p.y && wy <= p.y + this.NODE_H;
      }) || null;
    }

    resetView() { this.centerView(); this.render(); }
    toggleAst() { this.showAst = !this.showAst; this.render(); }
    toggleDfg() { this.showDfg = !this.showDfg; this.render(); }
  }

  function buildGraphPanelHtml(idx) {
    const finding = REPORT.findings[idx];
    if (!finding) return '';
    const graph = getCpgGraph(finding, idx);
    if (!graph || !graph.nodes || !graph.nodes.length) return '';
    const fid = `f${idx}`;
    const pruned = graph.pruned
      ? '<div class="pruned-warn">Graph pruned: showing the most relevant nodes around matched pattern nodes.</div>'
      : '';
    return `<div class="graph-panel">
      ${pruned}
      <div class="graph-controls">
        <button class="ctrl-btn" data-action="reset" data-fid="${fid}">Reset view</button>
        <button class="ctrl-btn" data-action="toggle-ast" data-fid="${fid}">AST edges</button>
        <button class="ctrl-btn" data-action="toggle-dfg" data-fid="${fid}">DFG edges</button>
        <button class="ctrl-btn" data-action="relayout" data-fid="${fid}">Re-layout</button>
      </div>
      <div class="legend">
        <span class="legend-item"><span class="legend-dot" style="background:#f85149;border:2px solid #ff7070"></span> Matched</span>
        <span class="legend-item"><span class="legend-dot" style="background:#58a6ff"></span> Identifier</span>
        <span class="legend-item"><span class="legend-dot" style="background:#a371f7"></span> Call</span>
        <span class="legend-item"><span class="legend-dot" style="background:#3fb950"></span> Declaration</span>
        <span class="legend-item"><span class="legend-dot" style="background:#aaaaaa"></span> Other</span>
      </div>
      <div class="graph-wrap" id="graph-wrap-${fid}">
        <canvas class="graph-canvas" id="graph-canvas-${fid}"></canvas>
      </div>
      <div class="graph-tooltip" id="graph-tooltip-${fid}"></div>
      <div class="hint">Scroll to zoom · drag to pan · click a node to view source.</div>
    </div>`;
  }

  function initGraphForFinding(idx) {
    const fid = `f${idx}`;
    if (graphInstances[fid]) return;
    const finding = REPORT.findings && REPORT.findings[idx];
    if (!finding) return;
    if (!document.getElementById(`graph-canvas-${fid}`)) return;
    const graph = getCpgGraph(finding, idx);
    if (!graph || !graph.nodes || !graph.nodes.length) return;
    graphInstances[fid] = new CpgGraphRenderer(
      fid,
      graph,
      finding.matched_node_ids || [],
      (finding.location && finding.location.file) || '',
    );
  }

  function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function sevBadge(sev) {
    return `<span class="sev-badge sev-${esc(sev)}">${esc(sev)}</span>`;
  }

  // ── Summary cards ─────────────────────────────────────────────────────────────

  function renderSummaryCards() {
    const { summary, metadata } = REPORT;
    const cards = [
      { label: 'Total Findings', value: summary.total_findings, color: null },
      { label: 'Files Scanned', value: metadata.files_scanned, color: null },
    ];

    // Severity breakdown cards
    for (const sev of SEV_ORDER) {
      const count = summary.by_severity[sev] ?? 0;
      if (count > 0) cards.push({ label: sev, value: count, color: SEV_COLORS[sev] });
    }

    const container = document.getElementById('summary-cards');
    container.innerHTML = cards.map(c => `
      <div class="summary-card">
        <div class="label">${esc(c.label)}</div>
        <div class="value" style="${c.color ? `color:${c.color}` : ''}">${c.value}</div>
      </div>`).join('');
  }

  // ── Source snippet drawer ─────────────────────────────────────────────────────

  const drawer = document.getElementById('snippet-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  const drawerTitle = document.getElementById('drawer-title');
  const drawerBody = document.getElementById('drawer-body');
  document.getElementById('drawer-close').addEventListener('click', closeDrawer);
  backdrop.addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

  function closeDrawer() {
    drawer.classList.remove('open');
    backdrop.classList.remove('open');
  }

  function openSnippet(file, line) {
    const key = `${file}:${line}`;
    const snippet = REPORT.snippets[key];
    drawerTitle.textContent = `${file}:${line}`;
    if (!snippet) {
      drawerBody.innerHTML = `<div class="drawer-error">Source not available.</div>`;
    } else {
      const { start_line, lines } = snippet;
      let html = '<pre class="snippet-code">';
      lines.forEach((ln, i) => {
        const lineNo = start_line + i;
        const isHighlight = lineNo === line;
        html += `<div class="snippet-line${isHighlight ? ' highlight' : ''}">` +
          `<span class="snippet-ln">${lineNo}</span>` +
          `<span class="snippet-txt">${esc(ln)}</span></div>`;
      });
      html += '</pre>';
      drawerBody.innerHTML = html;
    }
    drawer.classList.add('open');
    backdrop.classList.add('open');
    // Scroll to highlighted line
    const hl = drawerBody.querySelector('.highlight');
    if (hl) hl.scrollIntoView({ block: 'center' });
  }

  // ── Findings render ───────────────────────────────────────────────────────────

  function renderFinding(f, idx) {
    const sev = f.severity ?? 'info';
    const file = f.location?.file ?? '';
    const line = f.location?.line ?? 0;
    const endLine = f.location?.end_line ?? line;
    const lineRange = line === endLine ? `${line}` : `${line}–${endLine}`;
    const tags = (f.tags ?? []).map(t => `<span class="tag-pill">${esc(t)}</span>`).join('');
    const locStr = `${file}:${line}`;
    // Body is built lazily on first open
    return `
<details class="finding-item" data-idx="${idx}" data-sev="${esc(sev)}" data-rule="${esc(f.rule_id)}" data-msg="${esc(f.message)}">
  <summary>
    <div>
      <div class="finding-title">${esc(f.rule_id)}</div>
      <div class="finding-loc">${esc(file)}:${lineRange}</div>
      <div class="finding-msg">${esc(f.message)}</div>
    </div>
    ${sevBadge(sev)}
  </summary>
  <div class="finding-body"></div>
</details>`;
  }

  function buildFindingBodyHtml(f, idx) {
    const sev = f.severity ?? 'info';
    const file = f.location?.file ?? '';
    const line = f.location?.line ?? 0;
    const tags = (f.tags ?? []).map(t => `<span class="tag-pill">${esc(t)}</span>`).join('');
    const locStr = `${file}:${line}`;
    const graphHtml = buildGraphPanelHtml(idx);
    return `
    <div class="finding-header">
      <span class="rule-id">${esc(f.rule_id)}</span>
      ${sevBadge(sev)}
    </div>
    <div class="finding-message">${esc(f.message)}</div>
    <div>
      <a class="loc-link" data-file="${esc(file)}" data-line="${line}">${esc(locStr)}</a>
    </div>
    ${tags ? `<div class="tags-row">${tags}</div>` : ''}
    ${graphHtml}`;
  }

  function renderFindings(findings) {
    // Group by rule_id
    const byRule = {};
    findings.forEach((f, i) => {
      const key = f.rule_id ?? '(unknown)';
      if (!byRule[key]) byRule[key] = [];
      byRule[key].push({ f, i });
    });

    // Sort rule groups by highest severity first, then count
    const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const ruleKeys = Object.keys(byRule).sort((a, b) => {
      const ra = Math.min(...byRule[a].map(e => sevRank[e.f.severity ?? 'info'] ?? 4));
      const rb = Math.min(...byRule[b].map(e => sevRank[e.f.severity ?? 'info'] ?? 4));
      if (ra !== rb) return ra - rb;
      return byRule[b].length - byRule[a].length;
    });

    const root = document.getElementById('findings-root');
    if (findings.length === 0) {
      root.innerHTML = '<div class="no-findings">No findings.</div>';
      return;
    }

    root.innerHTML = `<div class="section-title">${findings.length} finding(s)</div>` +
      ruleKeys.map(rule => {
        const entries = byRule[rule];
        const topSev = entries.reduce((best, e) => {
          return (sevRank[e.f.severity ?? 'info'] ?? 4) < (sevRank[best] ?? 4) ? (e.f.severity ?? 'info') : best;
        }, 'info');
        return `
<details class="rule-group" open>
  <summary>
    <span>${esc(rule)} ${sevBadge(topSev)}</span>
    <span class="rule-badge">${entries.length}</span>
  </summary>
  <div class="finding-list">
    ${entries.map(({ f, i }) => renderFinding(f, i)).join('')}
  </div>
</details>`;
      }).join('');

    // Lazy build finding body on first open, then init graph
    root.addEventListener('toggle', (e) => {
      const details = e.target.closest('.finding-item');
      if (!details || !details.open) return;
      const body = details.querySelector('.finding-body');
      if (!body || body.dataset.loaded) return;
      const idx = parseInt(details.dataset.idx, 10);
      const f = REPORT.findings && REPORT.findings[idx];
      if (!f) return;
      body.innerHTML = buildFindingBodyHtml(f, idx);
      body.dataset.loaded = '1';
      // Wire loc-links inside this body
      body.querySelectorAll('.loc-link').forEach(a => {
        a.addEventListener('click', ev => {
          ev.preventDefault();
          openSnippet(a.dataset.file, Number(a.dataset.line));
        });
      });
      initGraphForFinding(idx);
    }, true);

    // Graph control buttons
    root.addEventListener('click', (e) => {
      const btn = e.target.closest('.ctrl-btn');
      if (!btn) return;
      const fid = btn.dataset.fid;
      const g = graphInstances[fid];
      if (!g) return;
      const action = btn.dataset.action;
      if (action === 'reset') g.resetView();
      else if (action === 'toggle-ast') g.toggleAst();
      else if (action === 'toggle-dfg') g.toggleDfg();
      else if (action === 'relayout') g.runLayout();
    });
  }

  // ── Filter / search ───────────────────────────────────────────────────────────

  function applyFilter() {
    const q = (document.getElementById('search-input').value ?? '').toLowerCase();
    const sev = document.getElementById('sev-filter').value;
    const filtered = REPORT.findings.filter(f => {
      if (sev && sev !== 'all' && (f.severity ?? 'info') !== sev) return false;
      if (q) {
        const text = [f.rule_id, f.message, f.location?.file ?? '', ...(f.tags ?? [])].join(' ').toLowerCase();
        if (!text.includes(q)) return false;
      }
      return true;
    });
    renderFindings(filtered);
  }

  // ── Init ──────────────────────────────────────────────────────────────────────

  document.addEventListener('DOMContentLoaded', () => {
    renderSummaryCards();
    renderFindings(REPORT.findings);

    document.getElementById('search-input').addEventListener('input', applyFilter);
    document.getElementById('sev-filter').addEventListener('change', applyFilter);
  });

}());
