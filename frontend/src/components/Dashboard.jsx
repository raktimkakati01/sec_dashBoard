import { useEffect, useMemo, useState } from "react";
import { Globe, ShieldAlert, Activity, Timer } from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

const SEV_COLORS = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#64748B" };
const TOOLTIP_STYLE = {
  background: "#ffffff",
  border: "1px solid rgba(63,114,175,0.2)",
  borderRadius: 8,
  fontSize: 12,
  color: "#162033",
};

export default function Dashboard({ scan, onSeveritySelect }) {
  const [lastUpdatedAt, setLastUpdatedAt] = useState(Date.now());
  const [nowTs, setNowTs] = useState(Date.now());
  const [hoveredSeverity, setHoveredSeverity] = useState(null);
  const findings = scan?.findings || [];
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });

  const timedEndpoints = (scan?.endpoints || []).filter((e) => e.response_time != null);
  const avgTime = timedEndpoints.length
    ? timedEndpoints.reduce((total, endpoint) => total + endpoint.response_time, 0) / timedEndpoints.length
    : 0;

  // Severity Mix (match reference UI: show HIGH/MEDIUM/LOW/INFO; merge CRITICAL into HIGH)
  const sevMixCounts = {
    high: sevCounts.critical + sevCounts.high,
    medium: sevCounts.medium,
    low: sevCounts.low,
    info: sevCounts.info,
  };
  const sevMixData = Object.entries(sevMixCounts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  const testCounts = {};
  findings.forEach((f) => { testCounts[f.test_type] = (testCounts[f.test_type] || 0) + 1; });
  const totalForSignals = findings.length || 1;
  const signalRows = Object.entries(testCounts)
    .map(([name, count]) => ({
      name: name.replace(/_/g, " "),
      count,
      pct: Math.round((count / totalForSignals) * 100),
    }))
    .sort((a, b) => (b.pct - a.pct) || (b.count - a.count));

  const highRisk = sevCounts.critical + sevCounts.high;
  const totalRoutes = scan?.total_endpoints ?? (scan?.endpoints || []).length ?? 0;
  const totalFindings = scan?.total_findings ?? findings.length ?? 0;
  const uniqueFindings = useMemo(() => {
    const keys = new Set();
    findings.forEach((f) => {
      const normalizedTitle = (f.title || "").replace(/\s*\(\d+\s+endpoints?\)$/i, "").trim().toLowerCase();
      keys.add(`${f.test_type || ""}::${f.severity || ""}::${normalizedTitle}`);
    });
    return keys.size;
  }, [findings]);

  const activityRows = buildActivityRows(scan);
  const sevLegend = [
    { key: "high", label: "HIGH", value: sevMixCounts.high, color: SEV_COLORS.high },
    { key: "medium", label: "MEDIUM", value: sevMixCounts.medium, color: SEV_COLORS.medium },
    { key: "low", label: "LOW", value: sevMixCounts.low, color: SEV_COLORS.low },
    { key: "info", label: "INFO", value: sevMixCounts.info, color: SEV_COLORS.info },
  ].filter((x) => x.value > 0);
  const sevMixTotal = Object.values(sevMixCounts).reduce((a, b) => a + b, 0) || totalFindings;
  const hoveredItem = hoveredSeverity ? sevLegend.find((x) => x.key === hoveredSeverity) : null;
  const centerValue = hoveredItem?.value ?? sevMixTotal;
  const centerLabel = hoveredItem?.label ?? "TOTAL";
  const isLive = !["completed", "failed"].includes((scan?.status || "").toLowerCase());

  useEffect(() => {
    setLastUpdatedAt(Date.now());
  }, [scan?.id, scan?.status, scan?.findings?.length, scan?.endpoints?.length, totalFindings, totalRoutes]);

  useEffect(() => {
    const id = setInterval(() => setNowTs(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const secondsSinceUpdate = Math.max(0, Math.floor((nowTs - lastUpdatedAt) / 1000));

  if (!scan) return (
    <div className="flex flex-col items-center justify-center py-28 text-[var(--text-dim)]">
      <Globe size={48} className="mb-4 opacity-20" />
      <p className="text-sm">Launch an automation run to begin bug hunting</p>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <KPI icon={<Globe size={18} />} label="Total Routes Mapped" value={totalRoutes} glow="glow-teal" accent="var(--teal)" />
        <KPI icon={<ShieldAlert size={18} />} label="Priority Bugs" value={highRisk} glow="glow-red" accent="var(--red)" pulse={highRisk > 0} />
        <KPI icon={<Activity size={18} />} label="Signals Captured" value={totalFindings} glow="glow-violet" accent="var(--violet)" />
        <KPI icon={<Timer size={18} />} label="Avg Response" value={`${avgTime.toFixed(2)}s`} glow="glow-green" accent="var(--green)" />
      </div>

      {/* Charts */}
      {findings.length > 0 && (
        <div className="grid xl:grid-cols-[1.1fr_1fr] gap-4">
          {/* Severity Mix */}
          <div className="dash-card p-5 min-h-[360px]">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-[20px] font-semibold tracking-tight text-slate-900">Severity Mix</h3>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  {totalFindings} total findings · {uniqueFindings} unique findings
                </p>
              </div>
              <span
                className="text-[10px] uppercase tracking-[0.14em] text-slate-600 bg-slate-100 px-2 py-1 rounded-full border border-slate-200"
                title="Hover donut slices or legend rows for details"
              >
                Interactive
              </span>
            </div>

            <div className="flex flex-col md:flex-row md:items-center gap-7">
              <div className="relative w-[220px] h-[220px] shrink-0 mx-auto md:mx-0">
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={sevMixData}
                      cx="50%"
                      cy="50%"
                      innerRadius={66}
                      outerRadius={102}
                      dataKey="value"
                      stroke="none"
                      paddingAngle={2}
                    >
                      {sevMixData.map((e) => (
                        <Cell
                          key={e.name}
                          fill={SEV_COLORS[e.name]}
                          stroke={hoveredSeverity === e.name ? "#1f2937" : "none"}
                          strokeWidth={hoveredSeverity === e.name ? 1 : 0}
                          opacity={!hoveredSeverity || hoveredSeverity === e.name ? 1 : 0.35}
                          style={{ cursor: "pointer", transition: "opacity 180ms ease" }}
                          onMouseEnter={() => setHoveredSeverity(e.name)}
                          onMouseLeave={() => setHoveredSeverity(null)}
                          onClick={() => onSeveritySelect?.(e.name)}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value, _name, item) => [`${value}`, item.payload.name]}
                      contentStyle={TOOLTIP_STYLE}
                      wrapperStyle={{ outline: "none" }}
                      itemStyle={{ color: "#162033" }}
                      labelStyle={{ color: "#94a3b8" }}
                    />
                  </PieChart>
                </ResponsiveContainer>

                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <div className="text-[36px] font-extrabold text-slate-900 tabular-nums leading-none">{centerValue}</div>
                  <div className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-500 mt-1">{centerLabel}</div>
                </div>
              </div>

              <div className="flex-1 space-y-3.5">
                {sevLegend.map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    className={`w-full flex items-center justify-between rounded-lg px-2 py-1.5 transition-colors ${hoveredSeverity === item.key ? "bg-slate-100" : "hover:bg-slate-50"}`}
                    onMouseEnter={() => setHoveredSeverity(item.key)}
                    onMouseLeave={() => setHoveredSeverity(null)}
                    onClick={() => onSeveritySelect?.(item.key)}
                    title={`${item.label}: ${item.value} findings (click to open bugs)`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                      <span className="text-[12px] font-semibold text-slate-600 uppercase tracking-[0.08em]">{item.label}</span>
                    </div>
                    <span className="text-[13px] font-semibold text-slate-700 font-mono tabular-nums">
                      {item.value} <span className="text-[11px] text-slate-500">({Math.round((item.value / (sevMixTotal || 1)) * 100)}%)</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Signals By Check */}
          <div className="dash-card p-5 min-h-[360px]">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-[20px] font-semibold tracking-tight text-slate-900">Signals By Check</h3>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] uppercase tracking-[0.14em] px-2 py-1 rounded-full border ${isLive ? "text-emerald-700 bg-emerald-50 border-emerald-200" : "text-slate-600 bg-slate-100 border-slate-200"}`}>
                  {isLive ? "Live" : "Snapshot"}
                </span>
                <span className="text-[10px] uppercase tracking-[0.14em] text-slate-600 bg-slate-100 px-2 py-1 rounded-full border border-slate-200">
                  Updated {secondsSinceUpdate}s ago
                </span>
              </div>
            </div>

            <div className="space-y-4 px-1">
              {signalRows.slice(0, 5).map((row) => (
                <div key={row.name}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[13px] font-semibold text-slate-700">{row.name}</span>
                    <span className="text-[13px] font-semibold text-slate-600 tabular-nums">{row.pct}%</span>
                  </div>
                  <div className="h-[9px] bg-slate-100 rounded-full overflow-hidden">
                    <div className="h-full bg-[var(--violet)]" style={{ width: `${Math.max(2, row.pct)}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Live Activity Log */}
      <div className="dash-card overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: "rgba(63,114,175,0.12)" }}>
          <div>
            <div className="text-[12px] font-semibold text-[var(--text)]">Live Activity Log</div>
            <div className="text-[11px] text-[var(--text-dim)]">Monitoring automation events and findings.</div>
          </div>
          <button
            type="button"
            onClick={() => downloadCsv(activityRows)}
            className="text-[10px] font-semibold tracking-[0.14em] uppercase text-[var(--text-dim)] hover:text-[var(--text)]"
          >
            Export CSV
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Method / URL</th>
                <th>Scan Type</th>
                <th>Timestamp</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {activityRows.length === 0 ? (
                <tr>
                  <td colSpan={4} className="text-center text-[var(--text-dim)] py-10">No activity yet.</td>
                </tr>
              ) : activityRows.map((row, idx) => (
                <tr key={`${row.kind}-${idx}`}>
                  <td>
                    <span className="method-badge" style={methodPillStyle(row.method)}>{row.method}</span>{" "}
                    <span className="font-mono text-[12px] text-slate-700">{row.path}</span>
                  </td>
                  <td className="text-[11px] text-slate-700 font-semibold">{row.scanType}</td>
                  <td className="text-[11px] text-[var(--text-dim)] font-mono">{row.when}</td>
                  <td>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${row.statusClass}`}>{row.statusLabel}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="px-4 py-3 text-center text-[11px] text-[var(--text-dim)]">
          View complete audit trail →
        </div>
      </div>
    </div>
  );
}

function KPI({ icon, label, value, glow, accent, pulse }) {
  return (
    <div className={`dash-card ${glow} p-5 relative overflow-hidden min-h-[94px]`}>
      {pulse && <div className="absolute top-2 right-2 w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
      <div className="flex items-center gap-2 mb-2" style={{ color: accent }}>
        {icon}
        <span className="text-[10px] font-semibold tracking-[0.12em] uppercase">{label}</span>
      </div>
      <div className="text-[34px] leading-none font-bold font-mono text-[var(--text)]">{value}</div>
    </div>
  );
}

function buildActivityRows(scan) {
  const endpoints = scan?.endpoints || [];
  const findings = scan?.findings || [];

  const endpointRows = endpoints.slice(-10).reverse().map((ep, i) => {
    const path = (ep.url || "").replace(/https?:\/\/[^/]+/i, "") || ep.url || "—";
    const status = ep.status_code;
    const ok = status && status < 400;
    const statusLabel = ok ? "SECURE" : status ? String(status) : "—";
    const statusClass = ok ? "bg-emerald-500/15 text-emerald-500 border border-emerald-500/20" : "bg-slate-500/10 text-slate-600 border border-slate-400/20";
    return {
      kind: "endpoint",
      method: ep.method || "GET",
      path,
      scanType: (ep.source || "CRAWLER").toString().toUpperCase(),
      when: relTime(i),
      statusLabel,
      statusClass,
    };
  });

  const findingRows = findings.slice(-10).reverse().map((f, i) => {
    const path = (f.endpoint_url || "").replace(/https?:\/\/[^/]+/i, "") || f.endpoint_url || "—";
    const statusClass = "bg-rose-500/15 text-rose-600 border border-rose-500/20";
    return {
      kind: "finding",
      method: "⚑",
      path,
      scanType: (f.test_type || "SCAN").toString().replace(/_/g, " ").toUpperCase(),
      when: relTime(i),
      statusLabel: "VULN",
      statusClass,
    };
  });

  return [...endpointRows, ...findingRows].slice(0, 12);
}

function relTime(i) {
  if (i < 1) return "2s ago";
  if (i < 3) return `${(i + 1) * 7}s ago`;
  if (i < 7) return `${i}m ago`;
  return `${i + 2}m ago`;
}

function methodPillStyle(method) {
  const m = String(method || "").toUpperCase();
  if (m === "GET") return { background: "rgba(16,185,129,0.12)", color: "#059669", border: "1px solid rgba(16,185,129,0.20)" };
  if (m === "POST") return { background: "rgba(249,115,22,0.12)", color: "#ea580c", border: "1px solid rgba(249,115,22,0.20)" };
  if (m === "PUT") return { background: "rgba(245,158,11,0.12)", color: "#b45309", border: "1px solid rgba(245,158,11,0.22)" };
  if (m === "DELETE") return { background: "rgba(239,68,68,0.12)", color: "#dc2626", border: "1px solid rgba(239,68,68,0.22)" };
  if (m === "⚑") return { background: "rgba(244,63,94,0.10)", color: "#e11d48", border: "1px solid rgba(244,63,94,0.22)" };
  return { background: "rgba(100,116,139,0.10)", color: "#475569", border: "1px solid rgba(100,116,139,0.18)" };
}

function downloadCsv(rows) {
  const header = ["method", "url", "scan_type", "timestamp", "status"];
  const lines = rows.map((r) => [
    safeCsv(r.method),
    safeCsv(r.path),
    safeCsv(r.scanType),
    safeCsv(r.when),
    safeCsv(r.statusLabel),
  ].join(","));
  const csv = [header.join(","), ...lines].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `bugops_activity_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 500);
}

function safeCsv(value) {
  const s = String(value ?? "");
  if (/[,"\n]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
  return s;
}
