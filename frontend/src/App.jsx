import { useState, useEffect, useCallback, useRef } from "react";
import { Shield, Activity, Radio, LogOut, LayoutDashboard, List, Radar, ScrollText, Settings, Plus, ShieldAlert } from "lucide-react";
import {
  clearStoredToken,
  getCurrentAdmin,
  getScans,
  getScan,
  getScanEndpoints,
  getScanFindings,
  getStoredToken,
  logoutAdmin,
} from "./api";
import AuthPage from "./components/AuthPage";
import ScanForm from "./components/ScanForm";
import Dashboard from "./components/Dashboard";
import EndpointList from "./components/EndpointList";
import VulnFindings from "./components/VulnFindings";
import ScanHistory from "./components/ScanHistory";

const NAV = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "endpoints", label: "Endpoints", icon: List },
  { id: "findings", label: "Bugs", icon: ShieldAlert },
  { id: "scans", label: "Scans", icon: Radar },
  { id: "logs", label: "Logs", icon: ScrollText },
  { id: "settings", label: "Settings", icon: Settings },
];

function useClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => { const id = setInterval(() => setTime(new Date()), 1000); return () => clearInterval(id); }, []);
  return time;
}

function CrawlerLog({ scan }) {
  const ref = useRef(null);
  const endpoints = scan?.endpoints || [];
  const findings = scan?.findings || [];
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [endpoints.length, findings.length]);

  const lines = [];
  endpoints.slice(-50).forEach((ep) => {
    const ok = ep.status_code && ep.status_code < 400;
    lines.push({ text: `${ep.method.padEnd(6)} ${ep.url.replace(/https?:\/\/[^/]+/, "")}`, tag: ok ? "[SECURE]" : `[${ep.status_code}]`, color: ok ? "text-emerald-400" : "text-amber-400" });
  });
  findings.slice(-20).forEach((f) => {
    lines.push({ text: `▸ ${f.title}`, tag: `[VULN]`, color: f.severity === "critical" ? "text-red-400" : f.severity === "high" ? "text-orange-400" : "text-amber-300" });
  });

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-3 py-2.5 border-b border-white/5">
        <Activity size={12} className="text-[var(--violet)]" />
        <span className="text-[10px] font-semibold tracking-[0.15em] uppercase text-[var(--violet)]">Crawler Log</span>
        <span className="ml-auto text-[10px] text-[var(--text-dim)] font-mono">{lines.length} events</span>
      </div>
      <div ref={ref} className="terminal-log flex-1 p-3 overflow-y-auto">
        {lines.length === 0 ? (
          <span className="text-[var(--text-dim)]">Waiting for automation events<span className="animate-pulse">_</span></span>
        ) : lines.map((l, i) => (
          <div key={i} className="flex justify-between gap-2"><span className="text-slate-500 truncate">{l.text}</span><span className={`shrink-0 font-semibold ${l.color}`}>{l.tag}</span></div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const clock = useClock();
  const [authLoading, setAuthLoading] = useState(true);
  const [admin, setAdmin] = useState(null);
  const [scans, setScans] = useState([]);
  const [activeScanId, setActiveScanId] = useState(null);
  const [activeScan, setActiveScan] = useState(null);
  const [activeNav, setActiveNav] = useState("dashboard");
  const [findingsSeverityFilter, setFindingsSeverityFilter] = useState("all");

  const handleUnauthorized = useCallback(() => {
    clearStoredToken();
    setAdmin(null);
    setScans([]);
    setActiveScan(null);
    setActiveScanId(null);
  }, []);

  const refreshScans = useCallback(async () => {
    try {
      const nextScans = await getScans();
      setScans(nextScans);
      setActiveScanId((currentId) => currentId ?? nextScans[0]?.id ?? null);
    } catch (error) {
      if (error?.status === 401) {
        handleUnauthorized();
      }
    }
  }, [handleUnauthorized]);

  const refreshActiveScan = useCallback(async () => {
    if (!activeScanId) {
      setActiveScan(null);
      return;
    }
    try {
      const detail = await getScan(activeScanId);
      const [endpoints, findings] = await Promise.all([
        getScanEndpoints(activeScanId),
        getScanFindings(activeScanId),
      ]);
      setActiveScan({
        ...detail,
        endpoints,
        findings,
      });
    } catch (error) {
      if (error?.status === 401) {
        handleUnauthorized();
        return;
      }
      setActiveScan(null);
    }
  }, [activeScanId, handleUnauthorized]);

  useEffect(() => {
    if (!getStoredToken()) {
      setAuthLoading(false);
      return;
    }

    getCurrentAdmin()
      .then((user) => setAdmin(user))
      .catch(() => clearStoredToken())
      .finally(() => setAuthLoading(false));
  }, []);

  useEffect(() => {
    if (!admin) {
      return;
    }
    refreshScans();
  }, [admin, refreshScans]);

  useEffect(() => {
    if (!admin) {
      return;
    }
    refreshActiveScan();
  }, [admin, activeScanId, refreshActiveScan]);

  useEffect(() => {
    if (!activeScan || activeScan.status === "completed" || activeScan.status === "failed") return;
    const id = setInterval(() => { refreshActiveScan(); refreshScans(); }, 3000);
    return () => clearInterval(id);
  }, [activeScan, refreshActiveScan, refreshScans]);

  const handleScanStarted = (scan) => {
    setActiveScanId(scan.id);
    setActiveScan({
      ...scan,
      endpoints: [],
      findings: [],
    });
    setScans((current) => [scan, ...current.filter((item) => item.id !== scan.id)]);
    setActiveNav("dashboard");
    refreshScans();
  };
  const isLive = activeScan && !["completed", "failed"].includes(activeScan.status);

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-sm text-[var(--text-dim)]" style={{ background: "var(--obsidian)" }}>
        Verifying operator session...
      </div>
    );
  }

  if (!admin) {
    return <AuthPage onAuthenticated={setAdmin} />;
  }

  async function handleLogout() {
    await logoutAdmin();
    handleUnauthorized();
  }

  return (
    <div className="app-shell">
      <div className="scanline-overlay" />

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="h-9 w-9 rounded-xl flex items-center justify-center border" style={{ background: "rgba(63,114,175,0.10)", borderColor: "rgba(63,114,175,0.18)" }}>
            <Shield size={18} className="text-[var(--violet)]" />
          </div>
          <div className="min-w-0">
            <div className="text-[15px] font-extrabold tracking-tight text-[var(--text)] leading-none">BUG<span className="text-[var(--violet)]">OPS</span></div>
            <div className="text-[10px] text-[var(--text-dim)] tracking-[0.22em] uppercase mt-1">Security Ops Suite</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV.map((item) => {
            const Icon = item.icon;
            const active = activeNav === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveNav(item.id);
                  if (item.id === "findings") {
                    setFindingsSeverityFilter("all");
                  }
                }}
                className={`sidebar-item ${active ? "active" : ""}`}
                type="button"
              >
                <Icon size={18} className={active ? "text-[var(--violet)]" : ""} />
                <span className="text-[13px] font-semibold">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <button
            type="button"
            className="sidebar-primary"
            onClick={() => setActiveNav("dashboard")}
            title="Start a new target run"
          >
            <Plus size={16} />
            New Target
          </button>

          <div className="sidebar-profile">
            <div className="sidebar-avatar" />
            <div className="min-w-0">
              <div className="text-[12px] font-semibold text-[var(--text)] truncate">{admin.email}</div>
              <div className="text-[10px] text-[var(--text-dim)] truncate">Operator</div>
            </div>
          </div>
        </div>
      </aside>

      {/* Content */}
      <div className="content">
        <div className="topbar">
          <div className="topbar-card w-full p-3">
            <div className="flex items-center gap-4">
              <div className="flex-1 min-w-0">
                <ScanForm onScanStarted={handleScanStarted} variant="topbar" />
              </div>

              <div className="hidden lg:flex items-center gap-4 shrink-0">
                {activeScan && (
                  <div className="flex items-center gap-2">
                    {isLive && <div className="live-dot" />}
                    <span className={`text-[10px] font-mono font-semibold tracking-wider ${isLive ? "text-[var(--teal)]" : "text-[var(--text-dim)]"}`}>
                      {isLive ? "LIVE" : activeScan.status.toUpperCase()}
                    </span>
                  </div>
                )}
                <div className="text-[11px] font-mono text-[var(--text-dim)] tabular-nums">{clock.toLocaleTimeString("en-US", { hour12: false })}</div>
                <button
                  onClick={handleLogout}
                  className="text-[10px] uppercase tracking-[0.14em] text-[var(--text-dim)] hover:text-[var(--text)] flex items-center gap-1.5"
                >
                  <LogOut size={12} />
                  Logout
                </button>
              </div>
            </div>
          </div>
        </div>

        <main className="page">
          {activeNav === "dashboard" && (
            <Dashboard
              scan={activeScan}
              onSeveritySelect={(severity) => {
                setFindingsSeverityFilter(severity || "all");
                setActiveNav("findings");
              }}
            />
          )}
          {activeNav === "endpoints" && <EndpointList endpoints={activeScan?.endpoints} />}
          {activeNav === "scans" && (
            <div className="section-card p-4">
              <div className="flex items-center gap-2 mb-3">
                <Radio size={12} className="text-[var(--violet)]" />
                <span className="text-[10px] font-semibold tracking-[0.15em] uppercase text-[var(--violet)]">Automation Runs</span>
              </div>
              <ScanHistory
                scans={scans}
                activeScanId={activeScanId}
                onSelect={(id) => { setActiveScanId(id); setActiveNav("dashboard"); }}
              />
            </div>
          )}
          {activeNav === "logs" && (
            <div className="section-card overflow-hidden">
              <CrawlerLog scan={activeScan} />
            </div>
          )}
          {activeNav === "settings" && (
            <div className="section-card p-6 max-w-3xl space-y-6">
              <div className="flex items-center gap-2">
                <Settings size={14} className="text-[var(--violet)]" />
                <span className="text-[10px] font-semibold tracking-[0.15em] uppercase text-[var(--violet)]">Settings</span>
              </div>
              <p className="text-sm text-[var(--text-dim)]">Configure scanner integrations and optional CLI tooling on the host that runs the backend.</p>
              <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-4 space-y-3">
                <h3 className="text-sm font-semibold text-slate-900">Scanner host & CLIs</h3>
                <ul className="text-[13px] text-slate-600 space-y-2 list-disc pl-5 leading-relaxed">
                  <li>
                    <strong className="text-slate-800">Nuclei</strong> — installed on this scanner host and available under <strong>Advanced</strong> when starting a scan.
                  </li>
                  <li>
                    <strong className="text-slate-800">404 surfaces</strong> — the Bugs screen lists crawled <strong>HTTP 404</strong> routes and groups 404-bypass-style findings separately from other issues.
                  </li>
                </ul>
              </div>
            </div>
          )}
          {activeNav === "findings" && (
            <VulnFindings
              findings={activeScan?.findings}
              endpoints={activeScan?.endpoints}
              filterSeverity={findingsSeverityFilter}
              onFilterChange={setFindingsSeverityFilter}
            />
          )}
        </main>
      </div>
    </div>
  );
}
