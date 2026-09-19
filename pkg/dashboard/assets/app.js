// The dashboard's entire client.
//
// Vanilla on purpose. The Content-Security-Policy allows script from this
// origin only, so a framework would have to be vendored into the image and
// carried forever; and the page's job is small enough that the framework would
// be the largest thing in it. There is no build step, no bundle, and no
// dependency to audit.
//
// Two rules hold throughout:
//
//   - Data never goes into innerHTML. Every value here is a container's
//     command line, a file path or a Kubernetes name, which is to say
//     attacker-influenced text. It is written with textContent, so the worst a
//     hostile path can do is look odd.
//   - The token is sent in the Authorization header and stored in
//     sessionStorage, never a cookie. A cookie would be attached by the
//     browser automatically, which is what makes cross-site request forgery
//     possible; a header the page sets deliberately is not.

"use strict";

const TOKEN_KEY = "pahlevan.token";

const state = {
  token: "",
  view: "overview",
  workload: null,
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setStatus(message, isError) {
  const node = document.getElementById("status");
  node.textContent = message || "";
  node.className = isError ? "status error" : "status";
}

function show(id) {
  for (const view of document.querySelectorAll(".view")) {
    view.hidden = view.id !== id;
  }
}

function markTab(name) {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.classList.toggle("active", tab.dataset.view === name);
  }
}

// api performs one authenticated read. Errors carry the server's own message,
// which names what failed and what to do about it, so the page never has to
// invent an explanation for a 403 it does not understand.
async function api(path) {
  if (!state.token) throw new Error("paste a Kubernetes token above to connect");
  const response = await fetch(path, {
    headers: { Authorization: "Bearer " + state.token, Accept: "application/json" },
    cache: "no-store",
  });
  if (response.status === 401) {
    throw new Error("the cluster did not accept that token; it may have expired");
  }
  if (!response.ok) {
    let message = "request failed with status " + response.status;
    try {
      const body = await response.json();
      if (body && body.error) message = body.error;
    } catch (err) {
      // A non-JSON error body is itself the finding; keep the status message.
    }
    throw new Error(message);
  }
  return response.json();
}

// svg fetches a server-rendered diagram and parses it into real nodes.
//
// DOMParser rather than innerHTML: the markup arrives from our own server, but
// parsing it as image/svg+xml means a document that is not SVG cannot become
// HTML in the page, and the browser's own parser decides what the bytes are
// rather than an assignment to a string property.
async function svg(path) {
  const response = await fetch(path, {
    headers: { Authorization: "Bearer " + state.token },
    cache: "no-store",
  });
  if (!response.ok) return null;
  const text = await response.text();
  const doc = new DOMParser().parseFromString(text, "image/svg+xml");
  const root = doc.documentElement;
  if (!root || root.nodeName.toLowerCase() !== "svg") return null;
  return document.importNode(root, true);
}

function card(value, label, tone) {
  const node = el("div", tone ? "card " + tone : "card");
  node.appendChild(el("div", "card-value", value));
  node.appendChild(el("div", "card-label", label));
  return node;
}

function phasePill(phase) {
  const pill = el("span", "pill pill-" + String(phase).toLowerCase(), phase);
  return pill;
}

function table(headers, rows) {
  const t = el("table");
  const thead = el("thead");
  const hr = el("tr");
  for (const h of headers) hr.appendChild(el("th", null, h));
  thead.appendChild(hr);
  t.appendChild(thead);
  const tbody = el("tbody");
  for (const row of rows) {
    const tr = el("tr");
    for (const cell of row) {
      if (cell instanceof Node) {
        const td = el("td");
        td.appendChild(cell);
        tr.appendChild(td);
      } else if (cell && typeof cell === "object") {
        const td = el("td", cell.className || null, cell.text);
        tr.appendChild(td);
      } else {
        tr.appendChild(el("td", null, cell));
      }
    }
    tbody.appendChild(tr);
  }
  t.appendChild(tbody);
  return t;
}

function panel(title, child) {
  const p = el("section", "panel");
  if (title) p.appendChild(el("h2", null, title));
  if (child) p.appendChild(child);
  return p;
}

async function renderOverview() {
  const data = await api("/api/overview");
  const root = document.getElementById("view-overview");
  root.replaceChildren();

  root.appendChild(el("h1", null, "What Pahlevan is doing"));

  const cards = el("div", "cards");
  cards.appendChild(card(data.workloads, "workloads"));
  cards.appendChild(card(data.containers.learning, "containers learning"));
  cards.appendChild(card(data.containers.enforcing, "containers enforcing", "ok"));
  cards.appendChild(card(data.denials.total, "denials", data.denials.total > 0 ? "deny" : null));
  cards.appendChild(card(data.namespaces.length, "namespaces you can read"));
  root.appendChild(cards);

  if (data.namespaces.length === 0) {
    root.appendChild(el("p", "hint",
      "Your account can list no namespace's Pahlevan resources. That is an RBAC answer, not an empty cluster."));
  } else {
    const rows = data.namespaces.map((ns) => [
      ns.namespace,
      { text: ns.policies, className: "num" },
      { text: ns.workloads, className: "num" },
      { text: ns.containers.learning, className: "num" },
      { text: ns.containers.enforcing, className: "num" },
      { text: ns.denials.total, className: ns.denials.total > 0 ? "num denied" : "num" },
      { text: ns.rollbacks, className: "num" },
      { text: ns.maxRisk, className: "num" },
    ]);
    root.appendChild(panel("By namespace", table(
      ["Namespace", "Policies", "Workloads", "Learning", "Enforcing", "Denied", "Rollbacks", "Max risk"], rows)));
  }

  if (!data.live) {
    root.appendChild(el("p", "hint",
      "No live event stream is wired to this dashboard, so denials are shown as the counts the agents report, without the process tree or the reason behind each one."));
  }
  show("view-overview");
}

async function renderWorkloads() {
  const data = await api("/api/workloads");
  const root = document.getElementById("view-workloads");
  root.replaceChildren();
  root.appendChild(el("h1", null, "Workloads"));

  if (!data.workloads || data.workloads.length === 0) {
    root.appendChild(el("p", "hint", "No container profile is visible to your account."));
    show("view-workloads");
    return;
  }

  const rows = data.workloads.map((w) => {
    const link = el("button", "link", w.namespace + "/" + w.name);
    link.type = "button";
    link.addEventListener("click", () => openWorkload(w));
    return [
      link,
      w.kind,
      phasePill(w.phase),
      { text: w.surface.syscallCount, className: "num" },
      { text: w.surface.fileCount, className: "num" },
      { text: w.surface.networkCount, className: "num" },
      { text: w.denials.total, className: w.denials.total > 0 ? "num denied" : "num" },
      { text: w.rollbacks, className: "num" },
    ];
  });
  root.appendChild(panel(null, table(
    ["Workload", "Kind", "Phase", "Syscalls", "Paths", "Destinations", "Denied", "Rollbacks"], rows)));
  show("view-workloads");
}

function workloadPath(w, prefix) {
  return prefix + "/" + encodeURIComponent(w.namespace) + "/" +
    encodeURIComponent(w.kind) + "/" + encodeURIComponent(w.name);
}

async function openWorkload(w) {
  state.workload = w;
  const detail = await api(workloadPath(w, "/api/workloads"));
  const root = document.getElementById("view-workload");
  root.replaceChildren();

  const back = el("button", "link", "back to workloads");
  back.type = "button";
  back.addEventListener("click", () => switchView("workloads"));
  root.appendChild(back);

  const heading = el("h1", null, detail.namespace + " / " + detail.kind + " / " + detail.name);
  root.appendChild(heading);

  const cards = el("div", "cards");
  cards.appendChild(card(detail.phase, "phase"));
  cards.appendChild(card(detail.containers.total, "containers"));
  cards.appendChild(card(detail.denials.total, "denials", detail.denials.total > 0 ? "deny" : null));
  cards.appendChild(card(detail.rollbacks, "rollbacks"));
  if (detail.attackSurface) cards.appendChild(card(detail.attackSurface.risk, "risk score"));
  root.appendChild(cards);

  const flowPanel = panel("Learning to enforcement", null);
  root.appendChild(flowPanel);
  const flowSVG = await svg(workloadPath(w, "/api/diagram/flow"));
  if (flowSVG) flowPanel.appendChild(flowSVG);

  const surfacePanel = panel("Learned surface", null);
  root.appendChild(surfacePanel);
  const surfaceSVG = await svg(workloadPath(w, "/api/diagram/surface"));
  if (surfaceSVG) surfacePanel.appendChild(surfaceSVG);
  surfacePanel.appendChild(chips("File paths", detail.surface.files));
  surfacePanel.appendChild(chips("Destinations", detail.surface.network));
  surfacePanel.appendChild(chips("Executables", detail.surface.executables));
  surfacePanel.appendChild(chips("Capabilities", detail.surface.capabilities));
  surfacePanel.appendChild(chips("Syscalls", detail.surface.syscalls));
  if (detail.surface.truncated) {
    surfacePanel.appendChild(el("p", "hint",
      "These lists are a sample. The counts above are the whole learned surface."));
  }

  const treePanel = panel("Process tree", null);
  root.appendChild(treePanel);
  const treeSVG = await svg(workloadPath(w, "/api/diagram/tree"));
  if (treeSVG) treePanel.appendChild(treeSVG);

  if (detail.denied && detail.denied.length > 0) {
    const rows = detail.denied.map((d) => [
      new Date(d.time).toLocaleTimeString(),
      d.kind,
      { text: d.subject, className: "mono" },
      { text: d.process + " (" + d.pid + ")", className: "mono" },
      { text: d.reason, className: "reason" },
    ]);
    root.appendChild(panel("What was denied, and why",
      table(["Time", "Kind", "Subject", "Process", "Reason"], rows)));
  } else {
    root.appendChild(panel("What was denied, and why",
      el("p", "hint", "Nothing has been denied for this workload in the events this dashboard has seen.")));
  }

  if (detail.containerViews && detail.containerViews.length > 0) {
    const rows = detail.containerViews.map((c) => [
      { text: c.name, className: "mono" },
      c.pod || "",
      c.node || "",
      phasePill(c.phase),
      { text: c.attempts, className: "num" },
      { text: c.rollbacks, className: "num" },
      c.rollbackReason || "",
    ]);
    root.appendChild(panel("Containers",
      table(["Profile", "Pod", "Node", "Phase", "Attempts", "Rollbacks", "Last rollback reason"], rows)));
  }

  markTab("workloads");
  show("view-workload");
}

function chips(label, values) {
  const wrap = el("div");
  wrap.appendChild(el("h3", null, label));
  if (!values || values.length === 0) {
    wrap.appendChild(el("p", "hint", "none learned"));
    return wrap;
  }
  const box = el("div", "chips");
  for (const v of values) box.appendChild(el("span", "chip", v));
  wrap.appendChild(box);
  return wrap;
}

async function renderDenials() {
  const data = await api("/api/denials");
  const root = document.getElementById("view-denials");
  root.replaceChildren();
  root.appendChild(el("h1", null, "What was denied, and why"));

  const cards = el("div", "cards");
  cards.appendChild(card(data.totals.total, "denials reported", data.totals.total > 0 ? "deny" : null));
  cards.appendChild(card(data.totals.files, "file"));
  cards.appendChild(card(data.totals.network, "network"));
  cards.appendChild(card(data.totals.execs, "exec"));
  cards.appendChild(card(data.totals.capabilities, "capability"));
  root.appendChild(cards);

  if (!data.live) {
    root.appendChild(el("p", "hint",
      "The counters above come from the agents' own profile status. Without a live event stream this dashboard cannot show the individual denials behind them."));
  }
  if (data.denials && data.denials.length > 0) {
    const rows = data.denials.map((d) => [
      new Date(d.time).toLocaleTimeString(),
      d.namespace + "/" + d.name,
      d.kind,
      { text: d.subject, className: "mono" },
      { text: d.ancestry || d.process, className: "mono" },
      { text: d.reason, className: "reason" },
    ]);
    root.appendChild(panel(null, table(
      ["Time", "Workload", "Kind", "Subject", "Process", "Reason"], rows)));
  }
  show("view-denials");
}

async function switchView(name) {
  state.view = name;
  markTab(name);
  try {
    setStatus("loading...");
    if (name === "overview") await renderOverview();
    else if (name === "workloads") await renderWorkloads();
    else if (name === "denials") await renderDenials();
    setStatus("");
  } catch (err) {
    setStatus(err.message, true);
    show("view-welcome");
  }
}

function connect() {
  const input = document.getElementById("token");
  const token = input.value.trim();
  if (!token) {
    setStatus("paste a Kubernetes bearer token first", true);
    return;
  }
  state.token = token;
  try {
    sessionStorage.setItem(TOKEN_KEY, token);
  } catch (err) {
    // A browser with storage disabled still works for this tab; the token
    // simply does not survive a reload. That is a smaller problem than
    // refusing to load.
  }
  input.value = "";
  switchView("overview");
}

function forget() {
  state.token = "";
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch (err) {
    // Nothing was stored, so nothing has to be removed.
  }
  show("view-welcome");
  markTab("");
  setStatus("token forgotten in this tab; it is still valid in the cluster until it expires or is revoked there");
}

function start() {
  document.getElementById("connect").addEventListener("click", connect);
  document.getElementById("forget").addEventListener("click", forget);
  document.getElementById("token").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") connect();
  });
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  }
  try {
    const saved = sessionStorage.getItem(TOKEN_KEY);
    if (saved) {
      state.token = saved;
      switchView("overview");
      return;
    }
  } catch (err) {
    // Storage is unavailable; fall through to the welcome panel.
  }
  show("view-welcome");
}

document.addEventListener("DOMContentLoaded", start);
