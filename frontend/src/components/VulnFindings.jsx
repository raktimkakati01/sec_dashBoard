import { useState, useMemo, useEffect } from "react";
import { ShieldAlert, ChevronDown, Route, ListTree, Bug } from "lucide-react";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function normalizeTitle(title) {
  return title.replace(/\s*\(\d+\s+endpoints?\)$/i, "").trim();
}

function normalizeFinding(finding) {
  return {
    ...finding,
    normalizedTitle: normalizeTitle(finding.title || ""),
  };
}

/** Same vulnerability type + severity → one card; URLs listed underneath. */
function groupByUniqueBug(findings) {
  const map = new Map();

  findings.forEach((raw) => {
    const f = normalizeFinding(raw);
    const key = `${f.test_type}::${f.normalizedTitle}::${f.severity}`;
    if (!map.has(key)) {
      map.set(key, {
        key,
        test_type: f.test_type,
        severity: f.severity,
        title: f.normalizedTitle,
        endpointUrls: new Set(),
        instances: [],
      });
    }
    const g = map.get(key);
    g.instances.push(f);
    if (f.endpoint_url) {
      g.endpointUrls.add(f.endpoint_url.trim());
    }
  });

  const groups = Array.from(map.values()).map((g) => ({
    ...g,
    endpointUrls: [...g.endpointUrls].sort((a, b) => a.localeCompare(b)),
    endpointCount: g.endpointUrls.size,
  }));

  groups.sort((a, b) => {
    const sd = (SEV_ORDER[a.severity] ?? 99) - (SEV_ORDER[b.severity] ?? 99);
    if (sd !== 0) return sd;
    return a.title.localeCompare(b.title);
  });

  return groups;
}

function isBypass404Finding(f) {
  const blob = `${f.test_type || ""} ${f.title || ""} ${f.description || ""} ${f.evidence || ""}`.toLowerCase();
  if (blob.includes("404 bypass") || blob.includes("bypass 404") || blob.includes("soft 404") || blob.includes("fake 404")) {
    return true;
  }
  if (blob.includes("bypass") && blob.includes("404")) return true;
  if (blob.includes("path") && blob.includes("normalization") && blob.includes("404")) return true;
  if (blob.includes("status") && blob.includes("manipulation") && blob.includes("404")) return true;
  return false;
}

function pickRepresentative(instanceArray) {
  if (!instanceArray.length) return null;
  return instanceArray.reduce((best, cur) => {
    const score = (cur.evidence?.length || 0) + (cur.description?.length || 0);
    const bestScore = (best.evidence?.length || 0) + (best.description?.length || 0);
    return score > bestScore ? cur : best;
  }, instanceArray[0]);
}

function buildEndpointLookup(endpoints) {
  const byUrl = new Map();
  (endpoints || []).forEach((ep) => {
    if (ep?.url && !byUrl.has(ep.url)) {
      byUrl.set(ep.url, ep);
    }
  });
  return byUrl;
}

function SectionHeading({ icon: Icon, title, subtitle }) {
  return (
    <div className="flex items-start gap-3 mb-4">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-slate-50">
        <Icon size={18} className="text-[var(--violet)]" />
      </div>
      <div className="min-w-0">
        <h2 className="text-[16px] font-semibold text-slate-900 tracking-tight">{title}</h2>
        {subtitle && <p className="text-[12px] text-slate-500 mt-0.5">{subtitle}</p>}
      </div>
    </div>
  );
}

function BugGroupCard({ group, section, expandedId, setExpandedId, endpointByUrl }) {
  const eid = `${section}:${group.key}`;
  const open = expandedId === eid;
  const rep = pickRepresentative(group.instances);
  const toggle = () => setExpandedId(open ? null : eid);

  return (
    <article className="rounded-2xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.06)] overflow-hidden">
      <button
        type="button"
        onClick={toggle}
        className="w-full text-left px-4 py-3.5 flex items-start gap-3 hover:bg-slate-50/90 transition-colors"
      >
        <div className="flex flex-col gap-2 min-w-[6.5rem] shrink-0 items-start">
          <span
            className={`sev-${group.severity} px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wide`}
          >
            {group.severity}
          </span>
          {!open && group.endpointUrls.length > 0 && (
            <span className="text-[10px] font-medium text-slate-500 bg-slate-50 border border-slate-200/80 px-2 py-0.5 rounded-full">
              {group.endpointCount} impacted
            </span>
          )}
        </div>

        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-[15px] font-semibold text-slate-900 leading-snug">{group.title}</span>
            <span className="text-[10px] font-mono text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded">
              {group.test_type.replace(/_/g, " ")}
            </span>
          </div>
          {!open && rep?.description && (
            <p className="text-[12px] text-slate-500 line-clamp-2">{rep.description}</p>
          )}
          {!open && group.endpointUrls.length > 0 && (
            <ul className="text-[11px] font-mono text-slate-600 space-y-0.5 max-h-20 overflow-hidden">
              {group.endpointUrls.slice(0, 3).map((url) => {
                const ep = endpointByUrl.get(url);
                const m = ep?.method ? `${ep.method} ` : "";
                return (
                  <li key={url} className="truncate" title={url}>
                    {m ? <span className="text-slate-400">{m}</span> : null}
                    {url}
                  </li>
                );
              })}
              {group.endpointUrls.length > 3 && (
                <li className="text-slate-400">+{group.endpointUrls.length - 3} more…</li>
              )}
            </ul>
          )}
        </div>
        <ChevronDown size={20} className={`text-slate-400 shrink-0 mt-0.5 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="px-4 pb-5 pt-4 bg-slate-50/70 border-t border-slate-100">
          <div className="space-y-4 text-[12px]">
            {rep?.description && (
              <div>
                <div className="text-[10px] font-bold tracking-[0.14em] text-slate-400 uppercase mb-2">
                  Description
                </div>
                <p className="text-slate-700 leading-relaxed">{rep.description}</p>
              </div>
            )}

            <div>
              <div className="text-[10px] font-bold tracking-[0.14em] text-slate-400 uppercase mb-2">
                Affected APIs
              </div>
              <div className="rounded-xl border border-slate-200/80 bg-white overflow-hidden">
                <ul className="max-h-48 overflow-y-auto divide-y divide-slate-100">
                  {group.endpointUrls.map((url) => {
                    const ep = endpointByUrl.get(url);
                    const method = ep?.method || null;
                    return (
                      <li key={url} className="px-4 py-2 font-mono text-[11px] text-slate-800 break-all">
                        {method ? (
                          <span className="inline-flex items-center justify-center min-w-[3.3rem] font-semibold text-slate-500 mr-2">
                            {method}
                          </span>
                        ) : null}
                        {url}
                      </li>
                    );
                  })}
                </ul>
              </div>
            </div>

            {rep?.evidence && (
              <div>
                <div className="text-[10px] font-bold tracking-[0.14em] text-slate-400 uppercase mb-2">
                  Sample evidence
                </div>
                <pre className="p-3 rounded-xl text-[11px] text-slate-700 overflow-x-auto whitespace-pre-wrap font-mono max-h-52 overflow-y-auto bg-white border border-slate-100">
                  {rep.evidence}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </article>
  );
}

export default function VulnFindings({ findings = [], endpoints = [], filterSeverity = "all", onFilterChange }) {
  const [filterSev, setFilterSev] = useState(filterSeverity || "all");
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    setFilterSev(filterSeverity || "all");
  }, [filterSeverity]);

  const endpointByUrl = useMemo(() => buildEndpointLookup(endpoints), [endpoints]);

  const notFoundRoutes = useMemo(
    () => (endpoints || []).filter((e) => e.status_code === 404).sort((a, b) => String(a.url).localeCompare(String(b.url))),
    [endpoints],
  );

  const filtered = useMemo(
    () => (filterSev === "all" ? findings : findings.filter((f) => f.severity === filterSev)),
    [findings, filterSev],
  );

  const mainFindings = useMemo(() => filtered.filter((f) => !isBypass404Finding(f)), [filtered]);
  const bypassFindings = useMemo(() => filtered.filter(isBypass404Finding), [filtered]);

  const mainGroups = useMemo(() => groupByUniqueBug(mainFindings), [mainFindings]);
  const bypassGroups = useMemo(() => groupByUniqueBug(bypassFindings), [bypassFindings]);

  const hasFindings = findings.length > 0;
  const show404Table = notFoundRoutes.length > 0;

  if (!hasFindings && !show404Table) {
    return (
      <div className="findings-page max-w-5xl space-y-6">
        <p className="text-[var(--text-dim)] text-center py-12 text-sm">No bugs flagged yet. Run automation on a target to populate findings and 404 routes.</p>
      </div>
    );
  }

  return (
    <div className="findings-page max-w-5xl space-y-10">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-[rgba(63,114,175,0.18)] bg-[rgba(63,114,175,0.08)]">
            <ShieldAlert size={18} className="text-[var(--violet)]" />
          </div>
          <div className="min-w-0">
            <h1 className="text-[15px] font-semibold text-[var(--text)] tracking-tight">Findings</h1>
            <p className="text-[12px] text-[var(--text-dim)] mt-0.5">
              <span className="font-medium text-slate-600">{mainGroups.length + bypassGroups.length}</span> unique issues ·{" "}
              <span className="font-medium text-slate-600">{filtered.length}</span> raw findings shown
                {filterSev !== "all" ? (
                <span className="text-slate-400"> · {findings.length} total in scan</span>
                ) : null}
              {" · "}
              <span className="font-medium text-slate-600">{notFoundRoutes.length}</span> 404{" "}
              {notFoundRoutes.length === 1 ? "route" : "routes"} from crawl
            </p>
          </div>
        </div>
        <label className="flex items-center gap-2 shrink-0">
          <span className="hidden sm:inline text-[11px] font-medium text-[var(--text-dim)]">Severity</span>
          <select
            value={filterSev}
            onChange={(e) => {
              const next = e.target.value;
              setFilterSev(next);
              onFilterChange?.(next);
              setExpandedId(null);
            }}
            className="pl-3 pr-8 py-2 text-[13px] font-medium text-slate-700 bg-white border border-slate-200 rounded-lg shadow-sm hover:border-slate-300 focus:ring-2 focus:ring-[rgba(63,114,175,0.35)] focus:border-[var(--violet)] cursor-pointer"
          >
            <option value="all">All severities</option>
            {Object.keys(SEV_ORDER).map((s) => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </label>
      </div>
      {mainGroups.length > 0 && (
        <section>
          <SectionHeading
            icon={Bug}
            title="Security findings"
            subtitle="One card per issue type. Expand to see every affected API."
          />
          <div className="space-y-3">
            {mainGroups.map((g) => (
              <BugGroupCard
                key={g.key}
                group={g}
                section="main"
                expandedId={expandedId}
                setExpandedId={setExpandedId}
                endpointByUrl={endpointByUrl}
              />
            ))}
          </div>
        </section>
      )}

      {!hasFindings && show404Table && (
        <p className="text-[12px] text-slate-500">No structured findings for this scan yet—404 table below comes from crawled routes only.</p>
      )}

      {filterSev !== "all" && filtered.length === 0 && findings.length > 0 && (
        <p className="text-[12px] text-amber-800 bg-amber-50/90 border border-amber-100 rounded-xl px-3 py-2">
          No findings match this severity. Switch back to “All severities”.
        </p>
      )}

      {bypassGroups.length > 0 && (
        <section>
          <SectionHeading
            icon={Route}
            title="404 bypass & routing signals"
            subtitle="Grouped issues that mention 404 handling, soft routes, or bypass patterns."
          />
          <div className="space-y-3">
            {bypassGroups.map((g) => (
              <BugGroupCard
                key={g.key}
                group={g}
                section="bypass"
                expandedId={expandedId}
                setExpandedId={setExpandedId}
                endpointByUrl={endpointByUrl}
              />
            ))}
          </div>
        </section>
      )}

      {show404Table && (
        <section>
          <SectionHeading
            icon={ListTree}
            title="404 responses from crawl"
            subtitle="Endpoints the mapper recorded as HTTP 404 (useful for tuning bypass checks and dead routes)."
          />
          <div className="rounded-2xl border border-slate-200/90 bg-white shadow-[0_1px_3px_rgba(15,23,42,0.06)] overflow-hidden">
            <div className="findings-404-scroll">
              <table className="findings-404-table">
                <thead>
                  <tr>
                    <th scope="col">Method</th>
                    <th scope="col">URL</th>
                    <th scope="col">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {notFoundRoutes.map((ep, i) => (
                    <tr key={`${ep.method}:${ep.url}:${i}`}>
                      <td>
                        <span className="font-mono text-[11px] font-semibold text-slate-600">{ep.method}</span>
                      </td>
                      <td className="font-mono text-[11px] text-slate-800 break-all">{ep.url}</td>
                      <td className="text-[11px] text-slate-500">{ep.source || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
