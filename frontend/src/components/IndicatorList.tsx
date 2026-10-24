/**
 * IndicatorList — renders detected phishing indicators with
 * colour-coded cards by risk contribution.
 */

import type { URLIndicator, MessageIndicator } from '../types/api';

type AnyIndicator = URLIndicator | MessageIndicator;

interface IndicatorListProps {
  indicators: AnyIndicator[];
  title?: string;
}

function getCardClass(contribution: string) {
  switch (contribution.toUpperCase()) {
    case 'HIGH':   return 'indicator-card-high';
    case 'MEDIUM': return 'indicator-card-medium';
    default:       return 'indicator-card-low';
  }
}

function getContributionStyle(contribution: string) {
  switch (contribution.toUpperCase()) {
    case 'HIGH':   return 'text-red-400 bg-red-500/10 border border-red-500/20';
    case 'MEDIUM': return 'text-amber-400 bg-amber-500/10 border border-amber-500/20';
    default:       return 'text-blue-400 bg-blue-500/10 border border-blue-500/20';
  }
}

function isMessageIndicator(ind: AnyIndicator): ind is MessageIndicator {
  return 'matched_text' in ind;
}

export default function IndicatorList({
  indicators,
  title = 'Detected Indicators',
}: IndicatorListProps) {
  if (indicators.length === 0) {
    return (
      <div className="text-center py-8">
        <div className="text-4xl mb-3">✓</div>
        <p className="text-emerald-400 font-medium">No phishing indicators detected</p>
        <p className="text-slate-500 text-sm mt-1">
          The analysis found no suspicious patterns. Always apply independent judgement.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
        {title} ({indicators.length})
      </h3>
      {indicators.map((ind, idx) => (
        <div
          key={`${ind.code}-${idx}`}
          className={`${getCardClass(ind.risk_contribution)} animate-slide-up`}
          style={{ animationDelay: `${idx * 50}ms` }}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <code className="text-xs font-mono text-slate-300 bg-slate-800/60 px-2 py-0.5 rounded">
                  {ind.code}
                </code>
                <span
                  className={`text-xs font-semibold px-2 py-0.5 rounded ${getContributionStyle(ind.risk_contribution)}`}
                >
                  {ind.risk_contribution}
                </span>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed">
                {ind.description}
              </p>
              {isMessageIndicator(ind) && ind.matched_text && (
                <div className="mt-2">
                  <span className="text-xs text-slate-500">Matched: </span>
                  <code className="text-xs font-mono text-amber-300 bg-amber-500/5 px-1.5 py-0.5 rounded border border-amber-500/20">
                    &quot;{ind.matched_text}&quot;
                  </code>
                </div>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
