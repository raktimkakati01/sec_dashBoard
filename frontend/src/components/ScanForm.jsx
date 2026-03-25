import { useState } from "react";
import { Search, KeyRound } from "lucide-react";
import { startScan } from "../api";

export default function ScanForm({ onScanStarted }) {
  const [url, setUrl] = useState("");
  const [cookies, setCookies] = useState("");
  const [extraHeaders, setExtraHeaders] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const hasAuth = cookies.trim() || extraHeaders.trim();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true); setError("");
    try {
      const scan = await startScan(url.trim(), cookies.trim() || null, extraHeaders.trim() || null);
      onScanStarted(scan); setUrl("");
    } catch (err) { setError(err.message || "Scan failed"); } finally { setLoading(false); }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-2.5">
      <div className="flex gap-2.5 items-end">
        <div className="flex-1 relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-dim)]" />
          <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://target.example.com" required
            className="w-full pl-9 pr-4 py-2 text-sm bg-[var(--obsidian)] border border-white/10 rounded-lg text-white placeholder-[var(--text-dim)] font-mono" />
        </div>
        <button type="button" onClick={() => setShowAuth(!showAuth)}
          className={`px-3 py-2 border rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
            showAuth || hasAuth ? "border-[var(--violet)] text-[var(--violet)] bg-[rgba(139,92,246,0.08)]" : "border-white/10 text-[var(--text-dim)] hover:border-white/20"
          }`}>
          <KeyRound size={13} />Auth{hasAuth ? " ✓" : ""}
        </button>
        <button type="submit" disabled={loading}
          className="px-5 py-2 bg-[var(--violet)] hover:bg-[#7C3AED] disabled:opacity-40 text-white text-xs font-bold tracking-wider uppercase rounded-lg transition-all shadow-[0_0_20px_rgba(139,92,246,0.3)]">
          {loading ? <span className="flex items-center gap-1.5"><span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />Scanning...</span> : "Initiate Scan"}
        </button>
      </div>

      {showAuth && (
        <div className="glass-card p-3.5 space-y-2.5">
          <p className="text-[10px] text-[var(--text-dim)]">Inject authentication headers. Copy from browser DevTools → Network → Request Headers.</p>
          <div>
            <label className="block text-[10px] font-semibold tracking-wide uppercase text-[var(--text-dim)] mb-1">Cookies</label>
            <textarea value={cookies} onChange={(e) => setCookies(e.target.value)} rows={2} placeholder="_session=eyJ...; XSRF-TOKEN=abc123"
              className="w-full px-3 py-1.5 text-xs bg-[var(--obsidian)] border border-white/10 rounded-md text-white placeholder-[var(--text-dim)] font-mono resize-y" />
          </div>
          <div>
            <label className="block text-[10px] font-semibold tracking-wide uppercase text-[var(--text-dim)] mb-1">Extra Headers <span className="normal-case font-normal">(one per line)</span></label>
            <textarea value={extraHeaders} onChange={(e) => setExtraHeaders(e.target.value)} rows={2} placeholder={"X-Xsrf-Token: 70bca44e...\nAuthorization: Bearer eyJ..."}
              className="w-full px-3 py-1.5 text-xs bg-[var(--obsidian)] border border-white/10 rounded-md text-white placeholder-[var(--text-dim)] font-mono resize-y" />
          </div>
        </div>
      )}
      {error && <p className="text-red-400 text-xs">{error}</p>}
    </form>
  );
}
