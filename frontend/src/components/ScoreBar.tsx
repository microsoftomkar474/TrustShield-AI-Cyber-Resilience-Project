/**
 * ScoreBar — animated horizontal bar showing risk score (0.0–1.0)
 */

import type { RiskLevel } from '../types/api';

interface ScoreBarProps {
  score: number;
  label: RiskLevel;
}

export default function ScoreBar({ score, label }: ScoreBarProps) {
  const pct = Math.round(score * 100);

  const fillClass =
    label === 'LOW'
      ? 'score-bar-fill-low bg-emerald-500'
      : label === 'MEDIUM'
      ? 'score-bar-fill-medium bg-amber-500'
      : label === 'HIGH'
      ? 'score-bar-fill-high bg-red-500'
      : 'score-bar-fill-unknown bg-slate-500';

  const textColor =
    label === 'LOW'
      ? 'text-emerald-400'
      : label === 'MEDIUM'
      ? 'text-amber-400'
      : label === 'HIGH'
      ? 'text-red-400'
      : 'text-slate-400';

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center text-sm">
        <span className="text-slate-400">Risk Score</span>
        <span className={`font-mono font-semibold ${textColor}`}>
          {score.toFixed(4)} ({pct}%)
        </span>
      </div>
      <div
        className="h-3 bg-slate-700/50 rounded-full overflow-hidden border border-slate-600/30"
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Risk score: ${pct}%`}
      >
        <div
          className={fillClass}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex justify-between text-xs text-slate-500">
        <span>0 — Safe</span>
        <span>0.28 — Medium</span>
        <span>0.45 — High</span>
        <span>1.0 — Max</span>
      </div>
      {label === 'UNKNOWN' && (
        <p className="text-xs text-slate-400 italic bg-slate-800/40 border border-slate-700/50 rounded p-2 mt-2">
          Assessment inconclusive: Threat intelligence feeds were unavailable and heuristic indicators are limited. Exercise caution.
        </p>
      )}
    </div>
  );
}
