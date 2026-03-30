import { Fragment, useState } from "react";
import { Lock } from "lucide-react";

const METHOD_BG = { GET: "bg-emerald-500/15 text-emerald-400", POST: "bg-blue-500/15 text-blue-400", PUT: "bg-amber-500/15 text-amber-400", PATCH: "bg-orange-500/15 text-orange-400", DELETE: "bg-red-500/15 text-red-400", OPTIONS: "bg-purple-500/15 text-purple-400", HEAD: "bg-slate-500/15 text-slate-400" };

function statusClass(c) { if (!c) return "text-[var(--text-dim)]"; if (c < 300) return "status-2xx"; if (c < 400) return "status-3xx"; if (c < 500) return "status-4xx"; return "status-5xx"; }

export default function EndpointList({ endpoints }) {
  const [sort, setSort] = useState("url");
  const [dir, setDir] = useState("asc");
  const [filter, setFilter] = useState("");
  const [expandedKey, setExpandedKey] = useState(null);

  if (!endpoints?.length) return <p className="text-[var(--text-dim)] text-center py-12 text-sm">No routes mapped yet.</p>;

  const toggle = (f) => { if (sort === f) setDir(dir === "asc" ? "desc" : "asc"); else { setSort(f); setDir("asc"); } };

  const filtered = endpoints.filter((e) => e.url.toLowerCase().includes(filter.toLowerCase()) || e.method.toLowerCase().includes(filter.toLowerCase()));
  const sorted = [...filtered].sort((a, b) => {
    const av = a[sort] ?? "", bv = b[sort] ?? "";
    const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
    return dir === "asc" ? cmp : -cmp;
  });

  const arrow = (f) => sort === f ? (dir === "asc" ? " ↑" : " ↓") : "";

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Lock size={14} className="text-[var(--violet)]" />
          <span className="text-[10px] font-semibold tracking-[0.15em] uppercase text-[var(--violet)]">
            Mapped Routes ({endpoints.length})
          </span>
        </div>
        <input type="text" placeholder="Filter..." value={filter} onChange={(e) => setFilter(e.target.value)}
          className="px-3 py-1.5 text-xs bg-white border border-[rgba(63,114,175,0.18)] rounded-md text-[var(--text)] placeholder-[var(--text-dim)] w-48" />
      </div>
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="cyber-table">
            <thead>
              <tr>
                <th onClick={() => toggle("method")}>Method{arrow("method")}</th>
                <th onClick={() => toggle("url")}>Endpoint{arrow("url")}</th>
                <th onClick={() => toggle("status_code")}>Status{arrow("status_code")}</th>
                <th onClick={() => toggle("response_time")}>Time{arrow("response_time")}</th>
                <th onClick={() => toggle("source")}>Source{arrow("source")}</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((ep, i) => (
                <Fragment key={`${ep.method}:${ep.url}:${i}`}>
                  <tr key={`row-${i}`}>
                    <td><span className={`method-badge ${METHOD_BG[ep.method] || "bg-slate-500/15 text-slate-400"}`}>{ep.method}</span></td>
                    <td><span className="font-mono text-[12px] text-slate-700">{ep.url}</span></td>
                    <td><span className={`font-mono font-semibold ${statusClass(ep.status_code)}`}>{ep.status_code ?? "—"}</span></td>
                    <td><span className="text-[var(--text-dim)] font-mono text-xs">{ep.response_time != null ? `${ep.response_time}s` : "—"}</span></td>
                    <td>
                      <button
                        type="button"
                        onClick={() => setExpandedKey(expandedKey === `${ep.method}:${ep.url}` ? null : `${ep.method}:${ep.url}`)}
                        className="text-[10px] text-[var(--violet)] hover:underline"
                      >
                        {expandedKey === `${ep.method}:${ep.url}` ? "Hide" : "Review"}
                      </button>
                    </td>
                  </tr>
                  {expandedKey === `${ep.method}:${ep.url}` && (
                    <tr key={`detail-${i}`}>
                      <td colSpan={5} className="bg-[rgba(63,114,175,0.04)]">
                        <div className="grid gap-3 py-2 md:grid-cols-2">
                          <div>
                            <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--text-dim)] mb-1">Request Content Type</div>
                            <div className="text-[11px] font-mono text-slate-700 break-all">{ep.request_content_type || "—"}</div>
                          </div>
                          <div>
                            <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--text-dim)] mb-1">Request Params</div>
                            <div className="text-[11px] font-mono text-slate-700 break-all">{ep.request_params || "—"}</div>
                          </div>
                          <div>
                            <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--text-dim)] mb-1">Request Example</div>
                            <pre className="text-[11px] font-mono text-slate-700 whitespace-pre-wrap break-words bg-white border border-slate-200 rounded p-2 overflow-x-auto">{ep.request_example || "—"}</pre>
                          </div>
                          <div>
                            <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--text-dim)] mb-1">Response Body Sample</div>
                            <pre className="text-[11px] font-mono text-slate-700 whitespace-pre-wrap break-words bg-white border border-slate-200 rounded p-2 overflow-x-auto">{ep.response_body_sample || "—"}</pre>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
