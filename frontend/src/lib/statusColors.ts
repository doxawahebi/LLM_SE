import type { RunStatus, Phase2Status, Phase3Status, Verdict } from "./types";

export const runStatusColor: Record<RunStatus, string> = {
  queued: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  running: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  paused: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  completed: "bg-green-500/20 text-green-300 border-green-500/30",
  failed: "bg-red-500/20 text-red-300 border-red-500/30",
  cancelled: "bg-gray-500/20 text-gray-300 border-gray-500/30",
  needs_build_config: "bg-purple-500/20 text-purple-300 border-purple-500/30",
};

export const phase2StatusColor: Record<Phase2Status, string> = {
  queued: "bg-yellow-500/20 text-yellow-300",
  exploring: "bg-blue-500/20 text-blue-300",
  authoring: "bg-indigo-500/20 text-indigo-300",
  refining: "bg-cyan-500/20 text-cyan-300",
  bug_triggered: "bg-orange-500/20 text-orange-300",
  inconclusive: "bg-gray-500/20 text-gray-300",
  likely_false_positive: "bg-gray-500/20 text-gray-400",
};

export const phase3StatusColor: Record<Phase3Status, string> = {
  queued: "bg-yellow-500/20 text-yellow-300",
  running: "bg-blue-500/20 text-blue-300",
  confirmed: "bg-green-500/20 text-green-300",
  rejected: "bg-red-500/20 text-red-300",
  skipped: "bg-gray-500/20 text-gray-400",
};

export const verdictColor: Record<NonNullable<Verdict>, string> = {
  CONFIRMED: "bg-green-500/20 text-green-300 border-green-500/30",
  inconclusive: "bg-gray-500/20 text-gray-300 border-gray-500/30",
  likely_false_positive: "bg-gray-500/20 text-gray-400 border-gray-500/20",
  rejected: "bg-red-500/20 text-red-300 border-red-500/30",
};
