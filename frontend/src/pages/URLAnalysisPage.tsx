/**
 * URLAnalysisPage — complete URL phishing analysis workflow
 *
 * Security: The user's URL is submitted as a string to the backend.
 * This component never navigates to or fetches from the submitted URL.
 */

import { useState } from 'react';
import { analyseURL } from '../services/api';
import type { URLScanResponse, AnalysisState } from '../types/api';
import RiskBadge from '../components/RiskBadge';
import ScoreBar from '../components/ScoreBar';
import IndicatorList from '../components/IndicatorList';
import ThreatIntelPanel from '../components/ThreatIntelPanel';

const MAX_URL_LENGTH = 2048;

function LoadingState() {
  return (
    <div className="glass-panel p-8 text-center animate-fade-in">
      <div className="relative inline-block mb-6">
        <div className="w-16 h-16 border-2 border-shield-accent/20 rounded-full" />
        <div className="absolute inset-0 w-16 h-16 border-2 border-transparent border-t-shield-accent rounded-full animate-spin" />
      </div>
      <h3 className="text-lg font-semibold text-slate-200 mb-2">Analysing URL...</h3>
      <p className="text-slate-400 text-sm">
        Running phishing checks and querying threat intelligence feeds.
      </p>
      <div className="mt-6 space-y-2">
        {['Parsing URL structure', 'Checking hostname patterns', 'Querying threat intelligence'].map((step, i) => (
          <div key={step} className="flex items-center gap-3 text-sm text-slate-400">
            <div
              className="w-2 h-2 rounded-full bg-shield-accent animate-pulse"
              style={{ animationDelay: `${i * 0.3}s` }}
            />
            {step}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function URLAnalysisPage() {
  const [url, setUrl] = useState('');
  const [state, setState] = useState<AnalysisState<URLScanResponse>>({
    status: 'idle',
    data: null,
    errorMessage: null,
  });
  const [activeTab, setActiveTab] = useState<'indicators' | 'ti' | 'parsed' | 'recs'>('indicators');

  const urlLength = url.trim().length;
  const isValidLength = urlLength > 0 && urlLength <= MAX_URL_LENGTH;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!isValidLength) return;

    setState({ status: 'loading', data: null, errorMessage: null });
    try {
      const result = await analyseURL(url.trim());
      setState({ status: 'success', data: result, errorMessage: null });
      setActiveTab('indicators');
    } catch (err) {
      setState({
        status: 'error',
        data: null,
        errorMessage: err instanceof Error ? err.message : 'An unexpected error occurred.',
      });
    }
  }

  function handleReset() {
    setState({ status: 'idle', data: null, errorMessage: null });
    setUrl('');
  }

  const data = state.data;

  return (
    <div className="space-y-6">
      {/* Input form */}
      <div className="glass-panel p-6">
        <h2 className="text-xl font-bold text-slate-100 mb-1">URL Phishing Analysis</h2>
        <p className="text-slate-400 text-sm mb-5">
          Submit a URL to check for phishing indicators. The URL is analysed as a string —
          it is never visited or loaded in the browser.
        </p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="url-input"
              className="block text-sm font-medium text-slate-300 mb-2"
            >
              URL to Analyse
            </label>
            <input
              id="url-input"
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com/login?ref=email"
              className="input-field font-mono text-sm"
              maxLength={MAX_URL_LENGTH}
              autoComplete="off"
              spellCheck={false}
              aria-describedby="url-helper"
              disabled={state.status === 'loading'}
            />
            <div
              id="url-helper"
              className="flex justify-between mt-1.5 text-xs"
            >
              <span className="text-slate-500">
                Supports http://, https://, and other schemes
              </span>
              <span className={urlLength > MAX_URL_LENGTH * 0.9 ? 'text-amber-400' : 'text-slate-600'}>
                {urlLength}/{MAX_URL_LENGTH}
              </span>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              id="url-analyse-btn"
              type="submit"
              disabled={!isValidLength || state.status === 'loading'}
              className="btn-primary flex-1"
            >
              {state.status === 'loading' ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Analysing…
                </>
              ) : (
                <>
                  <span>🔍</span>
                  Analyse URL
                </>
              )}
            </button>
            {state.status !== 'idle' && (
              <button
                id="url-reset-btn"
                type="button"
                onClick={handleReset}
                className="px-4 py-3 rounded-xl border border-shield-border text-slate-400
                  hover:text-slate-200 hover:border-slate-500 transition-all duration-200"
              >
                Reset
              </button>
            )}
          </div>
        </form>
      </div>

      {/* Loading state */}
      {state.status === 'loading' && <LoadingState />}

      {/* Error state */}
      {state.status === 'error' && (
        <div className="glass-panel p-6 border-red-500/30 animate-fade-in">
          <div className="flex items-start gap-3">
            <span className="text-red-400 text-xl mt-0.5">⚠</span>
            <div>
              <h3 className="font-semibold text-red-400 mb-1">Analysis Failed</h3>
              <p className="text-slate-300 text-sm">{state.errorMessage}</p>
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {state.status === 'success' && data && (
        <div className="space-y-5 animate-fade-in">
          {/* Summary card */}
          <div className="glass-panel p-6">
            <div className="flex items-start justify-between gap-4 flex-wrap mb-6">
              <div>
                <h3 className="text-lg font-bold text-slate-100 mb-1">Analysis Result</h3>
                <div className="font-mono text-xs text-slate-500 break-all max-w-lg">
                  {data.url_analysed}
                </div>
              </div>
              <RiskBadge level={data.label} size="lg" />
            </div>
            <ScoreBar score={data.score} label={data.label} />
            <div className="mt-4 flex gap-4 text-sm flex-wrap">
              <span className="text-slate-500">
                Score type: <span className="text-slate-300">{data.score_type}</span>
              </span>
              <span className="text-slate-500">
                Engine: <span className="text-slate-300 font-mono">{data.model_or_feed_version}</span>
              </span>
            </div>
          </div>

          {/* Tabbed detail panels */}
          <div className="glass-panel overflow-hidden">
            {/* Tab bar */}
            <div className="flex gap-1 p-3 border-b border-shield-border bg-slate-800/30">
              {[
                { id: 'indicators' as const, label: '🔍 Indicators', count: data.evidence.length },
                { id: 'ti' as const, label: '🌐 Threat Intel', count: data.threat_intelligence.length },
                { id: 'parsed' as const, label: '⚙ URL Details', count: null },
                { id: 'recs' as const, label: '💡 Recommendations', count: data.recommendations.length },
              ].map(tab => (
                <button
                  key={tab.id}
                  id={`url-tab-${tab.id}`}
                  onClick={() => setActiveTab(tab.id)}
                  className={activeTab === tab.id ? 'tab-btn-active' : 'tab-btn-inactive'}
                >
                  {tab.label}
                  {tab.count !== null && (
                    <span className={`text-xs px-1.5 py-0.5 rounded-full ${
                      activeTab === tab.id ? 'bg-white/20' : 'bg-slate-700'
                    }`}>
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </div>

            <div className="p-6">
              {/* Indicators tab */}
              {activeTab === 'indicators' && (
                <IndicatorList indicators={data.evidence} />
              )}

              {/* Threat Intel tab */}
              {activeTab === 'ti' && (
                <ThreatIntelPanel results={data.threat_intelligence} />
              )}

              {/* Parsed URL tab */}
              {activeTab === 'parsed' && (
                <div className="space-y-2">
                  <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">
                    Parsed URL Components
                  </h3>
                  <div className="rounded-xl overflow-hidden border border-shield-border">
                    <table className="w-full text-sm">
                      <tbody>
                        {Object.entries(data.parsed_components).map(([key, value], idx) => (
                          <tr
                            key={key}
                            className={idx % 2 === 0 ? 'bg-slate-800/40' : 'bg-slate-800/20'}
                          >
                            <td className="px-4 py-2.5 font-medium text-slate-400 w-32 capitalize">
                              {key.replace(/_/g, ' ')}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-slate-200 break-all">
                              {value !== null && value !== '' ? String(value) : (
                                <span className="text-slate-600 italic">—</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Recommendations tab */}
              {activeTab === 'recs' && (
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">
                    Recommendations ({data.recommendations.length})
                  </h3>
                  {data.recommendations.map((rec, idx) => (
                    <div
                      key={idx}
                      className="flex gap-3 p-4 rounded-xl border border-shield-border bg-slate-800/30"
                    >
                      <span className="text-shield-accent text-lg mt-0.5 shrink-0">💡</span>
                      <p className="text-slate-300 text-sm leading-relaxed">{rec}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Limitations notice */}
          <div className="glass-panel p-4 border-slate-600/30">
            <div className="flex gap-3">
              <span className="text-slate-500 text-sm mt-0.5 shrink-0">ℹ</span>
              <p className="text-slate-500 text-xs leading-relaxed">{data.limitations}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
