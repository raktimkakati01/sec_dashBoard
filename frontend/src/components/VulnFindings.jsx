import { useState } from "react";
import { ShieldAlert, ChevronDown } from "lucide-react";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Groups findings by (test_type + title) so duplicate vuln names collapse
 * into a single card showing count + expandable endpoint list.
 */
function groupFindings(findings) {
  const map = {};
  findings.forEach((f) => {
    // Normalize title: strip " (N endpoints)" suffix the backend may add
    const baseTitle = f.title.replace(/\s*\(\d+\s+endpoints?\)$/i, "");
    const key = `${f.test_type}::${baseTitle}::${f.severity}`;
    if (!map[key]) {
      map[key] = {
        key,
        test_type: f.test_type,
        title: baseTitle,
        severity: f.severity,
        description: f.description,
        evidence: f.evidence,
        endpoints: [],
        ids: [],
      };
    }
    map[key].endpoints.push(f.endpoint_url);
    map[key].ids.push(f.id);
    // Keep the most detailed evidence
    if (f.evidence && f.evidence.length > (map[key].evidence?.length || 0)) {
      map[key].evidence = f.evidence;
    }
  });
  return Object.values(map);
}

export default function VulnFindings({ findings }) {
  const [expandedKey, setExpandedKey] = useState(null);
  const [filterSev, setFilterSev] = useState("all");

  if (!findings?.length) return <p className="text-[var(--text-dim)] text-center py-12 text-sm">No vulnerabilities detected.</p>;

  const filtered = filterSev === "all" ? findings : findings.filter((f) => f.severity === filterSev);
  const groups = groupFindings(filtered);
  groups.sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

  // Group by test_type for section headers
  const byType = {};
  groups.forEach((g) => { if (!byType[g.test_type]) byType[g.test_type] = []; byType[g.test_type].push(g); });

  // Count unique vulns
  const uniqueCount = groups.length;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <ShieldAlert size={14} className="text-[var(--violet)]" />
          <span className="text-[10px] font-semibold tracking-[0.15em] uppercase text-[var(--violet)]">
            Vulnerabilities ({uniqueCount} unique / {findings.length} total)
          </span>
        </div>
        <select value={filterSev} onChange={(e) => setFilterSev(e.target.value)}
          className="px-3 py-1.5 text-xs bg-[var(--obsidian)] border border-white/10 rounded-md text-white">
          <option value="all">All Severities</option>
          {Object.keys(SEV_ORDER).map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
      </div>

      <div className="space-y-5">
        {Object.entries(byType).map(([type, items]) => (
          <div key={type}>
            <h4 className="text-[10px] font-semibold tracking-[0.12em] uppercase text-[var(--text-dim)] mb-2">
              {type.replace(/_/g, " ")} ({items.length})
            </h4>
            <div className="space-y-1.5">
              {items.map((g) => {
                const isOpen = expandedKey === g.key;
                const epCount = g.endpoints.length;
                const uniqueEps = [...new Set(g.endpoints)];

                return (
                  <div key={g.key} className="glass-card overflow-hidden">
                    <button onClick={() => setExpandedKey(isOpen ? null : g.key)}
                      className="w-full px-4 py-2.5 flex items-center justify-between text-left hover:bg-white/[0.02] transition-colors">
                      <div className="flex items-center gap-3">
                        <span className={`sev-${g.severity} px-2 py-0.5 rounded text-[10px] font-semibold capitalize`}>{g.severity}</span>
                        <span className="text-sm font-medium text-slate-200">{g.title}</span>
                        {epCount > 1 && (
                          <span className="text-[10px] font-mono text-[var(--text-dim)] bg-white/5 px-1.5 py-0.5 rounded">
                            {uniqueEps.length} endpoints
                          </span>
                        )}
                      </div>
                      <ChevronDown size={14} className={`text-[var(--text-dim)] transition-transform ${isOpen ? "rotate-180" : ""}`} />
                    </button>
                    {isOpen && (
                      <div className="px-4 pb-3 pt-2 border-t border-white/5 space-y-2">
                        {g.description && (
                          <div><span className="text-[10px] text-[var(--text-dim)]">Description: </span><span className="text-[11px] text-slate-400">{g.description}</span></div>
                        )}

                        {/* Affected endpoints list */}
                        <div>
                          <span className="text-[10px] text-[var(--text-dim)]">Affected Endpoints ({uniqueEps.length}):</span>
                          <div className="mt-1 max-h-40 overflow-y-auto rounded p-2 space-y-0.5" style={{ background: "rgba(5,7,12,0.6)" }}>
                            {uniqueEps.slice(0, 20).map((ep, i) => (
                              <div key={i} className="text-[11px] font-mono text-slate-400 truncate">• {ep}</div>
                            ))}
                            {uniqueEps.length > 20 && <div className="text-[11px] text-[var(--text-dim)]">... and {uniqueEps.length - 20} more</div>}
                          </div>
                        </div>

                        {g.evidence && (
                          <div>
                            <span className="text-[10px] text-[var(--text-dim)]">Evidence: </span>
                            <pre className="mt-1 p-2 rounded text-[11px] text-slate-400 overflow-x-auto whitespace-pre-wrap font-mono max-h-40 overflow-y-auto" style={{ background: "rgba(5,7,12,0.6)" }}>{g.evidence}</pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
