const STATUS_DOT = {
  pending: "bg-slate-500",
  crawling: "bg-amber-400 animate-pulse",
  scanning: "bg-[var(--violet)] animate-pulse",
  completed: "bg-emerald-400",
  failed: "bg-red-500",
};

export default function ScanHistory({ scans, activeScanId, onSelect }) {
  if (!scans?.length) return <p className="text-[var(--text-dim)] text-[11px] px-1">No scans initiated.</p>;

  return (
    <div className="space-y-1.5">
      {scans.map((s) => (
        <button key={s.id} onClick={() => onSelect(s.id)}
          className={`w-full text-left px-3 py-2.5 rounded-lg border transition-all ${
            s.id === activeScanId
              ? "bg-[rgba(139,92,246,0.08)] border-[var(--violet)]/40 shadow-[0_0_12px_rgba(139,92,246,0.1)]"
              : "bg-transparent border-white/5 hover:border-white/10"
          }`}>
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono font-medium text-slate-300 truncate max-w-[150px]">{s.base_url.replace(/https?:\/\//, "")}</span>
            <span className={`w-2 h-2 rounded-full shrink-0 ${STATUS_DOT[s.status] || "bg-slate-500"}`} />
          </div>
          <div className="flex items-center gap-2 mt-1 text-[10px] text-[var(--text-dim)] font-mono">
            <span>{s.total_endpoints} ep</span>
            <span className="opacity-30">·</span>
            <span>{s.total_findings} vln</span>
          </div>
        </button>
      ))}
    </div>
  );
}
