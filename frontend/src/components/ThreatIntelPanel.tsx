/**
 * ThreatIntelPanel — displays threat intelligence lookup results
 * from URLhaus and PhishTank.
 */

import type { ThreatIntelResult } from '../types/api';

interface ThreatIntelPanelProps {
  results: ThreatIntelResult[];
}

export default function ThreatIntelPanel({ results }: ThreatIntelPanelProps) {
  if (results.length === 0) {
    return (
      <div className="text-slate-500 text-sm italic">
        Threat intelligence lookups were not performed or were disabled.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {results.map((result, idx) => (
        <div
          key={idx}
          className="p-4 rounded-xl border border-shield-border bg-slate-800/30"
        >
          <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
            <span className="font-medium text-slate-200 text-sm">{result.source}</span>
            <div className="flex items-center gap-2">
              {result.is_mock && (
                <span className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 border border-purple-500/30">
                  MOCK
                </span>
              )}
              {result.error ? (
                <span className="text-xs px-2 py-0.5 rounded bg-slate-500/20 text-slate-400 border border-slate-500/30">
                  UNAVAILABLE
                </span>
              ) : result.found ? (
                <span className="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                  ⚠ FOUND IN FEED
                </span>
              ) : (
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  ✓ NOT IN FEED
                </span>
              )}
            </div>
          </div>
          {result.status && (
            <p className="text-xs text-slate-400 font-mono">{result.status}</p>
          )}
          {result.error && (
            <p className="text-xs text-slate-500 mt-1">{result.error}</p>
          )}
          {result.queried_at && (
            <p className="text-xs text-slate-600 mt-1">
              Queried: {new Date(result.queried_at).toLocaleTimeString()}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
