"use strict";

const AGGREGATORS = ["fedavg", "median", "trimmed_mean", "krum"];
const AGG_LABELS = { fedavg: "FedAvg", median: "Median", trimmed_mean: "Trimmed mean", krum: "Krum" };
const PRESET_LABELS = {
  baseline_iid: "No attack · IID data",
  baseline_noniid: "No attack · non-IID data",
  poison_fedavg: "Poisoning vs FedAvg",
  poison_median: "Poisoning vs Median",
  poison_trimmed_mean: "Poisoning vs Trimmed mean",
  poison_krum: "Poisoning vs Krum",
  poison_stealthy_fedavg: "Stealthy poisoning vs FedAvg",
};
const METRICS = [
  ["detection_rate", "c-detected"],
  ["false_alarm_rate", "c-false"],
  ["accuracy", "c-acc"],
];

const root = document.querySelector(".viz-root");
const form = document.getElementById("controls");
const $ = (id) => document.getElementById(id);
const css = (name) => getComputedStyle(root).getPropertyValue(name).trim();
const pct = (v) => `${(v * 100).toFixed(1)}%`;
const org = (cid) => `Org ${cid + 1}`;

let socket = null;
// Lines on the charts are only comparable when everything but the aggregator is equal.
let comparison = { signature: null, attackStart: null, rounds: 30, runs: {} };
let current = null;

const attackLine = {
  id: "attackLine",
  afterDatasetsDraw(chart) {
    if (!comparison.attackStart) return;
    const x = chart.scales.x.getPixelForValue(comparison.attackStart - 0.5);
    const { top, bottom } = chart.chartArea;
    const ctx = chart.ctx;
    ctx.save();
    ctx.strokeStyle = css("--muted");
    ctx.fillStyle = css("--muted");
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(x, top);
    ctx.lineTo(x, bottom);
    ctx.stroke();
    ctx.font = "11px system-ui, sans-serif";
    ctx.textAlign = "right";
    ctx.fillText("poisoning starts", x - 4, bottom - 6);
    ctx.restore();
  },
};

function makeChart(canvasId) {
  return new Chart($(canvasId), {
    type: "line",
    data: { datasets: [] },
    options: {
      animation: false,
      maintainAspectRatio: false,
      parsing: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: { type: "linear", min: 1, max: 30, ticks: { precision: 0 }, title: { display: true, text: "Round" } },
        y: { min: 0, max: 1, ticks: { stepSize: 0.25, callback: (v) => `${Math.round(v * 100)}%` } },
      },
      plugins: {
        legend: { display: false, position: "top", align: "start", labels: { boxWidth: 14, boxHeight: 2 } },
        tooltip: {
          callbacks: {
            title: (items) => `Round ${items[0].parsed.x}`,
            label: (item) => `${item.dataset.label}: ${pct(item.parsed.y)}`,
          },
        },
      },
      elements: { line: { borderWidth: 2, tension: 0, borderCapStyle: "round", borderJoinStyle: "round" } },
    },
    plugins: [attackLine],
  });
}

const charts = Object.fromEntries(METRICS.map(([metric, id]) => [metric, makeChart(id)]));

function applyTheme(chart) {
  const { x, y } = chart.options.scales;
  for (const axis of [x, y]) {
    axis.grid = { color: css("--grid"), drawTicks: false };
    axis.border = { color: css("--axis") };
    axis.ticks.color = css("--muted");
    axis.ticks.padding = 6;
  }
  x.grid.display = false;
  x.title.color = css("--text-secondary");
  chart.options.plugins.legend.labels.color = css("--text-secondary");
}

function dataset(agg, metric, records) {
  const color = css(`--agg-${agg}`);
  return {
    label: AGG_LABELS[agg],
    data: records.map((r) => ({ x: r.round, y: r[metric] })),
    borderColor: color,
    backgroundColor: color,
    pointBackgroundColor: color,
    pointBorderColor: css("--surface-1"),
    pointBorderWidth: 2,
    pointRadius: (ctx) => (ctx.dataIndex === ctx.dataset.data.length - 1 ? 4 : 0),
    pointHoverRadius: 5,
  };
}

function redraw() {
  const present = AGGREGATORS.filter((agg) => comparison.runs[agg]?.length);
  for (const [metric] of METRICS) {
    const chart = charts[metric];
    applyTheme(chart);
    chart.data.datasets = present.map((agg) => dataset(agg, metric, comparison.runs[agg]));
    chart.options.scales.x.max = comparison.rounds;
    chart.options.plugins.legend.display = present.length >= 2;
    chart.update("none");
  }
}

function params() {
  // Read fields directly: FormData silently drops disabled inputs.
  const get = (name) => form.elements.namedItem(name).value;
  const attack = get("attack");
  return {
    aggregator: get("aggregator"),
    partition: get("partition"),
    alpha: 0.5,
    n_clients: Number(get("n_clients")),
    rounds: Number(get("rounds")),
    attack,
    n_malicious: attack === "none" ? 0 : Number(get("n_malicious")),
    boost: attack === "none" ? 1 : Number(get("boost")),
    attack_start_round: Number(get("attack_start_round")),
  };
}

function signature(p) {
  const { aggregator, ...rest } = p;
  if (rest.attack === "none") delete rest.attack_start_round;
  return JSON.stringify(rest);
}

function describe(p) {
  const data = p.partition === "iid" ? "IID data" : "non-IID data (Dirichlet α 0.5)";
  const attack =
    p.attack === "none"
      ? "no attack"
      : `label-flip poisoning by ${p.n_malicious} organization${p.n_malicious === 1 ? "" : "s"}` +
        `${p.boost > 1 ? `, updates boosted ${p.boost}×` : ", unboosted"}, from round ${p.attack_start_round}`;
  return `${p.n_clients} organizations · ${data} · ${attack}`;
}

function setStatus(kind, text) {
  const el = $("status");
  el.classList.remove("good", "critical");
  if (kind) el.classList.add(kind);
  el.querySelector(".status-icon").textContent = kind === "critical" ? "⚠" : kind === "good" ? "✓" : "•";
  $("status-text").textContent = text;
}

function setRunning(running) {
  $("run").disabled = running;
  $("stop").disabled = !running;
}

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function buildOrgTable(info) {
  const body = $("orgs").querySelector("tbody");
  body.replaceChildren();
  const malicious = new Set(info.malicious);
  info.client_class_counts.forEach((counts, cid) => {
    const total = counts.reduce((a, b) => a + b, 0);
    const top = counts.indexOf(Math.max(...counts));
    const tr = document.createElement("tr");
    const barCell = document.createElement("td");
    barCell.className = "bar-cell";
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.style.width = "0";
    barCell.append(bar);
    tr.append(
      cell(org(cid)),
      cell(total.toLocaleString(), "num"),
      cell(`${info.classes[top]} ${Math.round((100 * counts[top]) / total)}%`),
      barCell,
      cell("–", "num"),
      cell("–"),
      cell(malicious.has(cid) ? "Attacker" : "honest", malicious.has(cid) ? "truth-attacker" : ""),
    );
    body.append(tr);
  });
}

function updateOrgTable(record) {
  const rows = $("orgs").querySelectorAll("tbody tr");
  const maxNorm = Math.max(...record.clients.map((c) => c.update_norm));
  record.clients.forEach((c, i) => {
    const cells = rows[i].children;
    cells[3].firstChild.style.width = `${(100 * c.update_norm) / maxNorm}%`;
    cells[3].title = `update norm ${c.update_norm.toFixed(3)}`;
    cells[4].textContent = c.outlier_score.toFixed(3);
    cells[5].textContent = c.flagged ? "⚠ Flagged" : "accepted";
    cells[5].className = c.flagged ? "verdict-flagged" : "";
  });
}

function addRoundRow(record) {
  const flagged = record.clients.filter((c) => c.flagged).map((c) => org(c.cid));
  const tr = document.createElement("tr");
  tr.append(
    cell(String(record.round), "num"),
    cell(pct(record.detection_rate), "num"),
    cell(pct(record.false_alarm_rate), "num"),
    cell(pct(record.accuracy), "num"),
    cell(flagged.join(", ") || "–"),
  );
  $("rounds").querySelector("tbody").append(tr);
}

function onRound(record) {
  current.records.push(record);
  redraw();
  $("t-round").textContent = `${record.round} / ${current.params.rounds}`;
  $("t-detected").textContent = pct(record.detection_rate);
  $("t-false").textContent = pct(record.false_alarm_rate);
  $("t-acc").textContent = pct(record.accuracy);
  updateOrgTable(record);
  addRoundRow(record);
  const flagged = record.clients.filter((c) => c.flagged).map((c) => org(c.cid));
  if (flagged.length) setStatus("critical", `Server flagged ${flagged.join(", ")} as anomalous`);
  else setStatus("good", "No anomalous updates seen by the server");
}

function start() {
  if (socket) socket.close();
  const p = params();
  const sig = signature(p);
  if (sig !== comparison.signature) {
    comparison = {
      signature: sig,
      attackStart: p.attack === "none" ? null : p.attack_start_round,
      rounds: p.rounds,
      runs: {},
    };
  }
  comparison.runs[p.aggregator] = [];
  current = { params: p, records: comparison.runs[p.aggregator] };
  redraw();

  $("scenario").textContent = describe(p);
  for (const id of ["t-round", "t-detected", "t-false", "t-acc"]) $(id).textContent = "–";
  $("rounds").querySelector("tbody").replaceChildren();
  setStatus(null, `Starting ${AGG_LABELS[p.aggregator]} run…`);
  setRunning(true);

  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/run`);
  socket = ws;
  ws.onopen = () => ws.send(JSON.stringify(p));
  ws.onmessage = (event) => {
    if (socket !== ws) return;
    const msg = JSON.parse(event.data);
    if (msg.type === "start") {
      buildOrgTable(msg);
      if (msg.malicious.length) {
        $("scenario").textContent =
          `${describe(p)} · attackers: ${msg.malicious.map(org).join(", ")} (unknown to the server)`;
      }
    } else if (msg.type === "round") {
      onRound(msg.record);
    } else if (msg.type === "error") {
      setStatus("critical", msg.message);
    }
  };
  ws.onclose = () => {
    if (socket === ws) {
      socket = null;
      setRunning(false);
    }
  };
}

async function loadPresets() {
  const presets = await (await fetch("/api/presets")).json();
  const select = $("preset");
  for (const name of Object.keys(PRESET_LABELS)) {
    if (!presets[name]) continue;
    const option = document.createElement("option");
    option.value = name;
    option.textContent = PRESET_LABELS[name];
    select.append(option);
  }
  select.addEventListener("change", () => {
    const preset = presets[select.value];
    if (!preset) return;
    for (const [key, value] of Object.entries(preset)) {
      const field = form.elements.namedItem(key);
      if (field) field.value = String(value);
    }
    syncAttackFields();
  });
}

function syncAttackFields() {
  const off = form.elements.namedItem("attack").value === "none";
  for (const name of ["n_malicious", "boost", "attack_start_round"]) form.elements.namedItem(name).disabled = off;
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  start();
});
form.addEventListener("input", (event) => {
  if (event.target.id !== "preset") $("preset").value = "";
  syncAttackFields();
});
$("stop").addEventListener("click", () => {
  if (socket) socket.close();
  setStatus(null, "Stopped");
});
$("clear").addEventListener("click", () => {
  comparison = { signature: null, attackStart: null, rounds: comparison.rounds, runs: {} };
  redraw();
});
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", redraw);

syncAttackFields();
redraw();
loadPresets();
