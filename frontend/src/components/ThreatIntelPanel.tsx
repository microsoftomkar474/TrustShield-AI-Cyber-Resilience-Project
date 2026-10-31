/**
 * ThreatIntelPanel — displays threat intelligence lookup results
 * from URLhaus and PhishTank.
 */

import type { ThreatIntelResult } from '../types/api';

interface ThreatIntelPanelProps {
  results: ThreatIntelResult[];
}

export default function ThreatIntelPanel({ results }: ThreatIntelPanelProps) {
  if (!results || results.length === 0) {
    return (
      <div className="text-slate-500 text-sm italic p-4 border border-slate-700/50 rounded-xl bg-slate-800/20">
        Threat intelligence lookups were not performed or were disabled.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {results.map((result, idx) => {
        // Determine the visual state using structured lookup_status or fallback to error/found
        const isUnavailable =
          result.lookup_status === 'ERROR' ||
          result.lookup_status === 'TIMEOUT' ||
          result.lookup_status === 'NOT_CONFIGURED' ||
          result.lookup_status === 'DISABLED' ||
          !!result.error;
        const isFound =
          result.lookup_status === 'MALICIOUS' ||
          (result.found && !isUnavailable);
        const isClean =
          result.lookup_status === 'CLEAN' ||
          (!result.found && !isUnavailable && !result.is_mock);

        const statusLabel =
          result.lookup_status === 'NOT_CONFIGURED'
            ? 'NOT CONFIGURED'
            : result.lookup_status === 'TIMEOUT'
            ? 'TIMEOUT'
            : result.lookup_status === 'DISABLED'
            ? 'DISABLED'
            : 'UNAVAILABLE';

        return (
          <div
            key={idx}
            className={`p-4 rounded-xl border transition-colors ${isFound
              ? 'border-red-500/50 bg-red-500/5'
              : isUnavailable
                ? 'border-amber-500/50 bg-amber-500/5'
                : 'border-slate-700 bg-slate-800/30'
              }`}
          >
            <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
              <span className="font-medium text-slate-200 text-sm flex items-center gap-2">
                {result.source}
              </span>

              <div className="flex items-center gap-2">
                {result.is_mock && (
                  <span className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 border border-purple-500/30 font-medium tracking-wide">
                    MOCK DATA
                  </span>
                )}

                {isUnavailable ? (
                  <span className="text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 font-medium tracking-wide flex items-center gap-1">
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                    {statusLabel}
                  </span>
                ) : isFound ? (
                  <span className="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 font-medium tracking-wide flex items-center gap-1">
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                    THREAT FOUND
                  </span>
                ) : isClean ? (
                  <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-medium tracking-wide flex items-center gap-1">
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /></svg>
                    NOT IN FEED
                  </span>
                ) : null}
              </div>
            </div>

            {result.status && (
              <p className="text-sm text-slate-300 font-mono mt-1">{result.status}</p>
            )}

            {result.error && (
              <p className="text-xs text-amber-400/80 mt-2 bg-amber-500/10 p-2 rounded">
                <strong>Note:</strong> {result.error} (Local analysis still applies).
              </p>
            )}

            {result.queried_at && (
              <p className="text-xs text-slate-500 mt-3 border-t border-slate-700/50 pt-2">
                Queried: {new Date(result.queried_at).toLocaleTimeString()}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}