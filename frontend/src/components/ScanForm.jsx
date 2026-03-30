import { useState } from "react";
import { Search, KeyRound, SlidersHorizontal } from "lucide-react";
import { startScan } from "../api";

export default function ScanForm({ onScanStarted, variant = "panel" }) {
  const [url, setUrl] = useState("");
  const [cookies, setCookies] = useState("");
  const [extraHeaders, setExtraHeaders] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [enableNuclei, setEnableNuclei] = useState(false);
  const [nucleiTags, setNucleiTags] = useState("exposure,misconfig,takeover,token-spray,tech,cve");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const hasAuth = cookies.trim() || extraHeaders.trim();
  const isTopbar = variant === "topbar";
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true); setError("");
    try {
      const scan = await startScan(
        url.trim(),
        cookies.trim() || null,
        extraHeaders.trim() || null,
        enableNuclei,
        nucleiTags.trim() || null,
      );
      onScanStarted(scan); setUrl("");
    } catch (err) { setError(err.message || "Scan failed"); } finally { setLoading(false); }
  };

  return (
    <form onSubmit={handleSubmit} className={isTopbar ? "w-full" : "space-y-3"}>
      <div className={isTopbar ? "topbar-scan" : "flex gap-2.5 items-end"}>
        <div className={isTopbar ? "topbar-search" : "flex-1 relative"}>
          <Search size={14} className={isTopbar ? "topbar-search-icon" : "absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-dim)]"} />
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://target.example.com"
            required
            className={isTopbar ? "topbar-search-input" : "w-full pl-9 pr-4 py-2 text-sm bg-white border border-[rgba(63,114,175,0.18)] rounded-lg text-[var(--text)] placeholder-[var(--text-dim)] font-mono"}
          />
        </div>

        <div className={isTopbar ? "topbar-actions" : "flex items-end gap-2.5"}>
          <button
            type="button"
            onClick={() => setShowAuth(!showAuth)}
            className={`px-3 py-2 border rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
              showAuth || hasAuth ? "border-[var(--violet)] text-[var(--violet)] bg-[rgba(63,114,175,0.08)]" : "border-[rgba(63,114,175,0.18)] text-[var(--text-dim)] hover:border-[rgba(63,114,175,0.32)]"
            }`}
            title="Auth context"
          >
            <KeyRound size={13} />Auth{hasAuth ? " ✓" : ""}
          </button>

          {isTopbar && (
            <button
              type="button"
              onClick={() => setShowAdvanced((v) => !v)}
              className={`px-3 py-2 border rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                showAdvanced || enableNuclei ? "border-[var(--violet)] text-[var(--violet)] bg-[rgba(63,114,175,0.08)]" : "border-[rgba(63,114,175,0.18)] text-[var(--text-dim)] hover:border-[rgba(63,114,175,0.32)]"
              }`}
              title="Advanced options"
            >
              <SlidersHorizontal size={13} />
              Advanced{enableNuclei ? " ✓" : ""}
            </button>
          )}

          <button
            type="submit"
            disabled={loading}
            className={isTopbar ? "topbar-run" : "px-5 py-2 bg-[var(--violet)] hover:bg-[#335f93] disabled:opacity-40 text-white text-xs font-bold tracking-wider uppercase rounded-lg transition-all shadow-[0_0_20px_rgba(63,114,175,0.3)]"}
          >
            {loading ? <span className="flex items-center gap-1.5"><span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />Launching...</span> : "Run Automation"}
          </button>
        </div>
      </div>

      {isTopbar && error && <p className="text-red-400 text-xs mt-2">{error}</p>}

      {(!isTopbar || showAdvanced) && (
        <div className="glass-card p-3.5 space-y-2.5 mt-3">
          <label className="flex items-center justify-between gap-3">
            <div>
              <div className="text-[10px] font-semibold tracking-wide uppercase text-[var(--text-dim)]">Nuclei</div>
              <div className="text-[11px] text-[var(--text-dim)]">Optional automation pack for quick bug signature coverage.</div>
            </div>
            <input
              type="checkbox"
              checked={enableNuclei}
              onChange={(e) => setEnableNuclei(e.target.checked)}
              className="h-4 w-4 accent-[var(--violet)]"
            />
          </label>
          <div>
            <label className="block text-[10px] font-semibold tracking-wide uppercase text-[var(--text-dim)] mb-1">
              Nuclei Tags
            </label>
            <input
              type="text"
              value={nucleiTags}
              onChange={(e) => setNucleiTags(e.target.value)}
              placeholder="exposure,misconfig,takeover,tech,cve"
              className="w-full px-3 py-1.5 text-xs bg-white border border-[rgba(63,114,175,0.18)] rounded-md text-[var(--text)] placeholder-[var(--text-dim)] font-mono"
            />
          </div>
        </div>
      )}

      {showAuth && (
        <div className="glass-card p-3.5 space-y-2.5 mt-3">
          <p className="text-[10px] text-[var(--text-dim)]">Inject authenticated context so the automation can hunt deeper workflow bugs.</p>
          <div>
            <label className="block text-[10px] font-semibold tracking-wide uppercase text-[var(--text-dim)] mb-1">Cookies</label>
            <textarea
              value={cookies}
              onChange={(e) => setCookies(e.target.value)}
              rows={2}
              placeholder="_session=eyJ...; XSRF-TOKEN=abc123"
              className="w-full px-3 py-1.5 text-xs bg-white border border-[rgba(63,114,175,0.18)] rounded-md text-[var(--text)] placeholder-[var(--text-dim)] font-mono resize-y"
            />
          </div>
          <div>
            <label className="block text-[10px] font-semibold tracking-wide uppercase text-[var(--text-dim)] mb-1">Extra Headers <span className="normal-case font-normal">(one per line)</span></label>
            <textarea
              value={extraHeaders}
              onChange={(e) => setExtraHeaders(e.target.value)}
              rows={2}
              placeholder={"X-Xsrf-Token: 70bca44e...\nAuthorization: Bearer eyJ..."}
              className="w-full px-3 py-1.5 text-xs bg-white border border-[rgba(63,114,175,0.18)] rounded-md text-[var(--text)] placeholder-[var(--text-dim)] font-mono resize-y"
            />
          </div>
        </div>
      )}

      {!isTopbar && error && <p className="text-red-400 text-xs">{error}</p>}
    </form>
  );
}
