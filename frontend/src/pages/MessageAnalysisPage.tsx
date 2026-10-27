import { useState } from 'react';
import type { FormEvent } from 'react';
import { analyseMessage } from '../services/api';
import type { MessageScanResponse, AnalysisState } from '../types/api';
import RiskBadge from '../components/RiskBadge';
import ScoreBar from '../components/ScoreBar';
import IndicatorList from '../components/IndicatorList';

const MAX_MESSAGE_LENGTH = 10000;

export default function MessageAnalysisPage() {
  const [message, setMessage] = useState('');
  const [state, setState] = useState<AnalysisState<MessageScanResponse>>({
    status: 'idle',
    data: null,
    errorMessage: null,
  });

  const trimmedMessage = message.trim();
  const isValid = trimmedMessage.length > 0 &&
    trimmedMessage.length <= MAX_MESSAGE_LENGTH;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!isValid || state.status === 'loading') return;

    setState({
      status: 'loading',
      data: null,
      errorMessage: null,
    });

    try {
      const result = await analyseMessage(trimmedMessage);

      setState({
        status: 'success',
        data: result,
        errorMessage: null,
      });
    } catch (error) {
      setState({
        status: 'error',
        data: null,
        errorMessage: error instanceof Error
          ? error.message
          : 'An unexpected error occurred.',
      });
    }
  }

  function handleReset() {
    setMessage('');
    setState({
      status: 'idle',
      data: null,
      errorMessage: null,
    });
  }

  const result = state.data;

  return (
    <main className="space-y-6">
      {/* Input Section */}
      <section className="glass-panel p-8 relative overflow-hidden">
        {/* Decorative top border */}
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-transparent opacity-80" />

        <h2 className="text-2xl font-bold text-white mb-2 tracking-tight flex items-center gap-2">
          <svg className="w-6 h-6 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
          Suspicious Message Analysis
        </h2>
        <p className="text-slate-400 text-sm mb-6 max-w-2xl">
          Analyse SMS, email, or chat text for potential phishing indicators.
          <span className="text-cyan-400 font-medium ml-1">Do not submit passwords or sensitive personal information.</span>
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="message-input"
              className="block text-sm font-medium text-slate-300 mb-2"
            >
              Message to analyse
            </label>
            <textarea
              id="message-input"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              maxLength={MAX_MESSAGE_LENGTH}
              rows={6}
              placeholder="Paste the suspicious message here..."
              className="input-field font-mono resize-y"
              aria-describedby="message-help"
            />
            <div
              id="message-help"
              className="flex justify-between mt-1.5 text-xs"
            >
              <span className="text-slate-500">
                Text will be analysed using rule-based heuristics.
              </span>
              <span className={message.length > MAX_MESSAGE_LENGTH * 0.9 ? 'text-amber-400' : 'text-slate-600'}>
                {message.length}/{MAX_MESSAGE_LENGTH} chars
              </span>
            </div>
          </div>

          {message.length > 0 && !isValid && (
            <p className="text-sm text-amber-300" role="alert">
              Enter a valid message within the character limit.
            </p>
          )}

          <div className="flex gap-3">
            <button
              type="submit"
              disabled={!isValid || state.status === 'loading'}
              className="btn-primary flex-1"
            >
              {state.status === 'loading' ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Analysing…
                </>
              ) : (
                <>
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                  Analyse Message
                </>
              )}
            </button>

            {state.status !== 'idle' && (
              <button
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
      </section>

      {/* Loading State */}
      {state.status === 'loading' && (
        <section className="glass-panel p-8 text-center animate-fade-in" role="status">
          <div className="relative inline-block mb-4">
            <div className="w-12 h-12 border-2 border-cyan-500/20 rounded-full" />
            <div className="absolute inset-0 w-12 h-12 border-2 border-transparent border-t-cyan-400 rounded-full animate-spin" />
          </div>
          <p className="text-slate-300">
            Analysing message for phishing indicators...
          </p>
        </section>
      )}

      {/* Error State */}
      {state.status === 'error' && (
        <section className="glass-panel p-6 border-red-500/30 animate-fade-in" role="alert">
          <div className="flex items-start gap-3">
            <span className="text-red-400 text-xl mt-0.5">⚠</span>
            <div>
              <h3 className="font-semibold text-red-400 mb-1">Analysis Failed</h3>
              <p className="text-slate-300 text-sm">{state.errorMessage}</p>
            </div>
          </div>
        </section>
      )}

      {/* Results */}
      {result && state.status === 'success' && (
        <section className="glass-panel p-8 space-y-6 animate-fade-in">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-700/50 pb-4">
            <div>
              <h3 className="text-lg font-bold text-slate-100">Analysis Result</h3>
              <p className="mt-1 text-sm font-mono text-slate-400 truncate max-w-lg">
                {result.message_preview}
              </p>
            </div>
            <RiskBadge level={result.label} size="lg" />
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between gap-3">
              <span className="text-sm text-slate-400">Risk score</span>
              <span className="font-mono font-bold text-slate-100">
                {(result.score * 100).toFixed(1)}%
              </span>
            </div>

            <ScoreBar score={result.score} label={result.label} />
            <p className="mt-2 text-xs text-slate-500">
              Score type: <span className="text-slate-400">{result.score_type}</span> · Engine: <span className="font-mono text-slate-400">{result.model_or_feed_version}</span>
            </p>
          </div>

          <div>
            <h4 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">
              Detected Indicators ({result.evidence.length})
            </h4>

            {result.evidence.length > 0 ? (
              <IndicatorList indicators={result.evidence} />
            ) : (
              <div className="p-4 rounded-xl border border-slate-700 bg-slate-800/30 text-center">
                <p className="text-emerald-400 font-medium">✓ No phishing indicators detected</p>
                <p className="text-sm text-slate-400 mt-1">This does not guarantee the message is safe.</p>
              </div>
            )}
          </div>

          {result.extracted_urls.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">
                URLs Found in Message
              </h4>

              <ul className="space-y-3">
                {result.extracted_urls.map((item, index) => (
                  <li
                    key={`${item.url}-${index}`}
                    className="rounded-xl border border-slate-700 bg-slate-800/30 p-4"
                  >
                    <p className="break-all text-sm font-mono text-cyan-300">
                      {item.url}
                    </p>

                    {item.scan_result ? (
                      <div className="mt-3 flex items-center gap-2">
                        <span className="text-xs text-slate-500">URL scan result:</span>
                        <RiskBadge level={item.scan_result.label} />
                        <span className="text-xs font-mono text-slate-400">
                          {(item.scan_result.score * 100).toFixed(1)}%
                        </span>
                      </div>
                    ) : (
                      <p className="mt-2 text-xs text-slate-500">
                        No URL scan result available.
                      </p>
                    )}
                  </li>
                ))}
              </ul>

              <p className="mt-3 text-xs text-slate-500 italic">
                URLs are displayed for inspection and are not opened automatically.
              </p>
            </div>
          )}

          {result.recommendations.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">
                Recommendations
              </h4>

              <ul className="space-y-2">
                {result.recommendations.map((recommendation, index) => (
                  <li key={index} className="flex gap-3 text-sm text-slate-300">
                    <span className="text-cyan-500 shrink-0">•</span>
                    {recommendation}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.limitations && (
            <div className="border-t border-slate-700/50 pt-4 mt-2">
              <div className="flex gap-2">
                <svg className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                <p className="text-xs leading-relaxed text-slate-500">
                  {result.limitations}
                </p>
              </div>
            </div>
          )}

          {result.error && (
            <p className="text-sm text-amber-400 bg-amber-500/10 p-3 rounded-lg" role="status">
              <strong>Note:</strong> {result.error}
            </p>
          )}
        </section>
      )}
    </main>
  );
}