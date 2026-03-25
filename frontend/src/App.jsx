import { useState, useEffect, useCallback, useRef } from "react";
import { Shield, Activity, Radio } from "lucide-react";
import { getScans, getScan } from "./api";
import ScanForm from "./components/ScanForm";
import Dashboard from "./components/Dashboard";
import EndpointList from "./components/EndpointList";
import VulnFindings from "./components/VulnFindings";
import ScanHistory from "./components/ScanHistory";

const TABS = ["Overview", "Endpoints", "Findings"];

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
        <span className="ml-auto text-[10px] text-[var(--text-dim)] font-mono">{lines.length} entries</span>
      </div>
      <div ref={ref} className="terminal-log flex-1 p-3 overflow-y-auto">
        {lines.length === 0 ? (
          <span className="text-[var(--text-dim)]">Awaiting scan data<span className="animate-pulse">_</span></span>
        ) : lines.map((l, i) => (
          <div key={i} className="flex justify-between gap-2"><span className="text-slate-500 truncate">{l.text}</span><span className={`shrink-0 font-semibold ${l.color}`}>{l.tag}</span></div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const clock = useClock();
  const [scans, setScans] = useState([]);
  const [activeScanId, setActiveScanId] = useState(null);
  const [activeScan, setActiveScan] = useState(null);
  const [activeTab, setActiveTab] = useState("Overview");

  const refreshScans = useCallback(async () => { try { setScans(await getScans()); } catch {} }, []);
  const refreshActiveScan = useCallback(async () => { if (!activeScanId) return; try { setActiveScan(await getScan(activeScanId)); } catch {} }, [activeScanId]);

  useEffect(() => { refreshScans(); }, [refreshScans]);
  useEffect(() => { refreshActiveScan(); }, [activeScanId, refreshActiveScan]);
  useEffect(() => {
    if (!activeScan || activeScan.status === "completed" || activeScan.status === "failed") return;
    const id = setInterval(() => { refreshActiveScan(); refreshScans(); }, 3000);
    return () => clearInterval(id);
  }, [activeScan, refreshActiveScan, refreshScans]);

  const handleScanStarted = (s) => { setActiveScanId(s.id); setActiveTab("Overview"); refreshScans(); };
  const isLive = activeScan && !["completed", "failed"].includes(activeScan.status);

  return (
    <div className="h-screen flex flex-col" style={{ background: "var(--obsidian)" }}>
      <div className="scanline-overlay" />

      {/* Header */}
      <header className="flex items-center justify-between px-6 py-2.5 border-b border-white/5 shrink-0" style={{ background: "rgba(11,14,20,0.9)", backdropFilter: "blur(12px)" }}>
        <div className="flex items-center gap-3">
          <Shield size={20} className="text-[var(--violet)]" />
          <span className="text-sm font-bold tracking-tight text-white">CYBER<span className="text-[var(--violet)]">OPS</span></span>
          <span className="hidden md:inline text-[9px] text-[var(--text-dim)] tracking-[0.2em] uppercase ml-1">Endpoint Security Scanner</span>
        </div>
        <div className="flex items-center gap-5">
          {activeScan && (
            <div className="flex items-center gap-2">
              {isLive && <div className="live-dot" />}
              <span className={`text-[10px] font-mono font-semibold tracking-wider ${isLive ? "text-[var(--teal)]" : "text-[var(--text-dim)]"}`}>
                {isLive ? "LIVE" : activeScan.status.toUpperCase()}
              </span>
              <span className="text-[10px] text-[var(--text-dim)] font-mono hidden lg:inline">{activeScan.base_url}</span>
            </div>
          )}
          <div className="text-[11px] font-mono text-[var(--text-dim)] tabular-nums">{clock.toLocaleTimeString("en-US", { hour12: false })}</div>
        </div>
      </header>

      {/* Scan Form */}
      <div className="px-6 py-3 border-b border-white/5 shrink-0" style={{ background: "var(--obsidian-light)" }}>
        <ScanForm onScanStarted={handleScanStarted} />
      </div>

      {/* Body */}
      <div className="flex flex-1 overflow-hidden">
        <aside className="w-60 shrink-0 border-r border-white/5 overflow-y-auto p-3" style={{ background: "var(--obsidian-light)" }}>
          <div className="flex items-center gap-2 mb-3 px-1">
            <Radio size={11} className="text-[var(--violet)]" />
            <span className="text-[9px] font-semibold tracking-[0.15em] uppercase text-[var(--violet)]">Scan History</span>
          </div>
          <ScanHistory scans={scans} activeScanId={activeScanId} onSelect={(id) => { setActiveScanId(id); setActiveTab("Overview"); }} />
        </aside>

        <main className="flex-1 min-w-0 overflow-y-auto p-5">
          {activeScan && (
            <div className="flex gap-1 mb-4">
              {TABS.map((tab) => (
                <button key={tab} onClick={() => setActiveTab(tab)}
                  className={`px-3.5 py-1.5 text-[10px] font-semibold tracking-[0.1em] uppercase rounded-md transition-all ${
                    activeTab === tab ? "bg-[rgba(139,92,246,0.12)] text-[var(--violet)] shadow-[0_0_12px_rgba(139,92,246,0.15)]" : "text-[var(--text-dim)] hover:text-white/60"
                  }`}>{tab}</button>
              ))}
            </div>
          )}
          {activeTab === "Overview" && <Dashboard scan={activeScan} />}
          {activeTab === "Endpoints" && <EndpointList endpoints={activeScan?.endpoints} />}
          {activeTab === "Findings" && <VulnFindings findings={activeScan?.findings} />}
        </main>

        <aside className="w-72 shrink-0 border-l border-white/5 overflow-hidden hidden xl:flex flex-col" style={{ background: "var(--obsidian-light)" }}>
          <CrawlerLog scan={activeScan} />
        </aside>
      </div>
    </div>
  );
}
