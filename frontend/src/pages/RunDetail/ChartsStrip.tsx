import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import type { Run } from "@/lib/types";

interface Props { run: Run }

export function ChartsStrip({ run }: Props) {
  // Stub data structures — live data comes via SSE
  const outcomeData = [
    {
      time: "now",
      bug_triggered: run.counters.specs_phase2_bug_triggered,
      inconclusive: run.counters.specs_phase2_inconclusive,
      likely_fp: run.counters.specs_phase2_likely_fp,
      error: run.counters.specs_phase2_errored,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 mt-4">
      <ChartCard title="Phase 2 Outcomes">
        <ResponsiveContainer width="100%" height={120}>
          <AreaChart data={outcomeData} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <XAxis dataKey="time" hide />
            <YAxis hide />
            <Tooltip
              contentStyle={{ background: "#1e2433", border: "1px solid #2e3547", fontSize: 11 }}
            />
            <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} />
            <Area
              type="monotone" dataKey="bug_triggered"
              stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.3}
            />
            <Area
              type="monotone" dataKey="inconclusive"
              stackId="1" stroke="#6b7280" fill="#6b7280" fillOpacity={0.3}
            />
            <Area
              type="monotone" dataKey="likely_fp"
              stackId="1" stroke="#4b5563" fill="#4b5563" fillOpacity={0.3}
            />
            <Area
              type="monotone" dataKey="error"
              stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.3}
            />
          </AreaChart>
        </ResponsiveContainer>
      </ChartCard>

      <ChartCard title="Turn Distribution">
        <ResponsiveContainer width="100%" height={120}>
          <BarChart data={[]} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <XAxis dataKey="turn" hide />
            <YAxis hide />
            <Tooltip
              contentStyle={{ background: "#1e2433", border: "1px solid #2e3547", fontSize: 11 }}
            />
            <Bar dataKey="count" fill="#3b82f6" />
          </BarChart>
        </ResponsiveContainer>
        <p className="text-xs text-muted-foreground text-center mt-1">
          Turn distribution data available when run completes
        </p>
      </ChartCard>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-card border border-border rounded-lg p-3">
      <p className="text-xs font-semibold text-muted-foreground mb-2">{title}</p>
      {children}
    </div>
  );
}
