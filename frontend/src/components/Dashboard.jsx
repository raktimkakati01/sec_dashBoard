import { Globe, ShieldAlert, Activity, Timer } from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";

const SEV_COLORS = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", info: "#64748B" };

export default function Dashboard({ scan }) {
  if (!scan) return (
    <div className="flex flex-col items-center justify-center py-28 text-[var(--text-dim)]">
      <Globe size={48} className="mb-4 opacity-20" />
      <p className="text-sm">Initialize a scan to begin threat analysis</p>
    </div>
  );

  const findings = scan.findings || [];
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });

  const avgTime = (scan.endpoints || []).filter((e) => e.response_time).reduce((a, e, _, arr) => a + e.response_time / arr.length, 0);

  const pieData = Object.entries(sevCounts).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }));
  const testCounts = {};
  findings.forEach((f) => { testCounts[f.test_type] = (testCounts[f.test_type] || 0) + 1; });
  const barData = Object.entries(testCounts).map(([name, count]) => ({ name: name.replace(/_/g, " "), count }));

  const highRisk = sevCounts.critical + sevCounts.high;

  return (
    <div>
      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <KPI icon={<Globe size={18} />} label="Endpoints Found" value={scan.total_endpoints} glow="glow-teal" accent="var(--teal)" />
        <KPI icon={<ShieldAlert size={18} />} label="High-Risk Vulns" value={highRisk} glow="glow-red" accent="var(--red)" pulse={highRisk > 0} />
        <KPI icon={<Activity size={18} />} label="Total Findings" value={scan.total_findings} glow="glow-violet" accent="var(--violet)" />
        <KPI icon={<Timer size={18} />} label="Avg Response" value={`${avgTime.toFixed(2)}s`} glow="glow-green" accent="var(--green)" />
      </div>

      {/* Severity breakdown */}
      <div className="grid grid-cols-5 gap-2 mb-6">
        {Object.entries(sevCounts).map(([sev, count]) => (
          <div key={sev} className="glass-card p-3 text-center">
            <div className="text-xl font-bold font-mono" style={{ color: SEV_COLORS[sev] }}>{count}</div>
            <div className="text-[9px] uppercase tracking-widest text-[var(--text-dim)] mt-1">{sev}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      {findings.length > 0 && (
        <div className="grid md:grid-cols-2 gap-4">
          <div className="glass-card p-4">
            <h3 className="text-[10px] font-semibold tracking-[0.15em] uppercase text-[var(--violet)] mb-3">Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={90} dataKey="value" stroke="none"
                  label={({ name, value, cx, x }) => (
                    <text x={x} y={undefined} fill="#E2E8F0" fontSize={12} fontFamily="'JetBrains Mono', monospace" textAnchor={x > cx ? "start" : "end"} dominantBaseline="central">
                      {name}: {value}
                    </text>
                  )}>
                  {pieData.map((e) => <Cell key={e.name} fill={SEV_COLORS[e.name]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#111520", border: "1px solid rgba(139,92,246,0.2)", borderRadius: 8, fontSize: 12, color: "#E2E8F0" }} itemStyle={{ color: "#E2E8F0" }} labelStyle={{ color: "#94a3b8" }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="glass-card p-4">
            <h3 className="text-[10px] font-semibold tracking-[0.15em] uppercase text-[var(--violet)] mb-3">Findings by Test</h3>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={barData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(139,92,246,0.08)" />
                <XAxis dataKey="name" tick={{ fill: "#64748B", fontSize: 10 }} angle={-15} textAnchor="end" />
                <YAxis tick={{ fill: "#64748B", fontSize: 10 }} />
                <Tooltip contentStyle={{ background: "#111520", border: "1px solid rgba(139,92,246,0.2)", borderRadius: 8, fontSize: 12, color: "#E2E8F0" }} itemStyle={{ color: "#E2E8F0" }} labelStyle={{ color: "#94a3b8" }} />
                <Bar dataKey="count" fill="var(--violet)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
}

function KPI({ icon, label, value, glow, accent, pulse }) {
  return (
    <div className={`glass-card ${glow} p-4 relative overflow-hidden`}>
      {pulse && <div className="absolute top-2 right-2 w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
      <div className="flex items-center gap-2 mb-2" style={{ color: accent }}>{icon}<span className="text-[9px] font-semibold tracking-[0.12em] uppercase">{label}</span></div>
      <div className="text-2xl font-bold font-mono text-white">{value}</div>
    </div>
  );
}
