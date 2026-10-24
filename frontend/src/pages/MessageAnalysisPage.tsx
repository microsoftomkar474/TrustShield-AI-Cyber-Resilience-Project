import { useState } from 'react';
import { analyseMessage } from '../services/api';
import type { MessageScanResponse, AnalysisState } from '../types/api';

export default function MessageAnalysisPage() {
  const [message, setMessage] = useState('');
  const [state, setState] = useState<AnalysisState<MessageScanResponse>>({
    status: 'idle',
    data: null,
    errorMessage: null,
  });

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const text = message.trim();
    if (!text || text.length > 10000) return;

    setState({ status: 'loading', data: null, errorMessage: null });

    try {
      const data = await analyseMessage(text);
      setState({ status: 'success', data, errorMessage: null });
    } catch (error) {
      setState({
        status: 'error',
        data: null,
        errorMessage: error instanceof Error ? error.message : 'Analysis failed.',
      });
    }
  }

  const result = state.data;

  return (
    <div className="space-y-6">
      <section className="glass-panel p-6">
        <h2 className="mb-2 text-xl font-bold text-slate-100">
          Suspicious Message Analysis
        </h2>

        <p className="mb-5 text-sm text-slate-400">
          Analyse SMS, email, or chat text for potential phishing indicators.
          Do not submit passwords or sensitive personal information.
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <label
            htmlFor="message-input"
            className="block text-sm font-medium text-slate-300"
          >
            Message to analyse
          </label>

          <textarea
            id="message-input"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            maxLength={10000}
            rows={7}
            required
            placeholder="Paste a suspicious message here..."
            className="w-full rounded-xl border border-slate-700 bg-slate-900 p-4 text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
          />

          <p className="text-right text-xs text-slate-500">
            {message.length}/10000
          </p>

          <div className="flex gap-3">
            <button
              type="submit"
              disabled={!message.trim() || state.status === 'loading'}
              className="flex-1 rounded-xl bg-blue-600 px-5 py-3 font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {state.status === 'loading' ? 'Analysing...' : 'Analyse Message'}
            </button>

            <button
              type="button"
              onClick={() => {
                setMessage('');
                setState({ status: 'idle', data: null, errorMessage: null });
              }}
              className="rounded-xl border border-slate-700 px-5 py-3 text-slate-300 hover:bg-slate-800"
            >
              Reset
            </button>
          </div>
        </form>
      </section>

      {state.status === 'error' && (
        <section
          role="alert"
          className="rounded-xl border border-red-500/40 bg-red-500/10 p-5 text-red-300"
        >
          {state.errorMessage}
        </section>
      )}

      {result && (
        <section className="glass-panel space-y-6 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h3 className="text-lg font-bold text-slate-100">
              Analysis Result
            </h3>

            <span className="rounded-full border border-slate-700 px-4 py-2 text-sm font-bold">
              {result.label} RISK
            </span>
          </div>

          <div>
            <div className="mb-2 flex justify-between text-sm">
              <span className="text-slate-400">Risk score</span>
              <strong>{(result.score * 100).toFixed(1)}%</strong>
            </div>

            <div
              className="h-3 overflow-hidden rounded-full bg-slate-800"
              role="progressbar"
              aria-label="Message risk score"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.max(0, Math.min(100, result.score * 100))}
            >
              <div
                className="h-full rounded-full bg-blue-500"
                style={{
                  width: `${Math.max(0, Math.min(100, result.score * 100))}%`,
                }}
              />
            </div>

            <p className="mt-2 text-xs text-slate-500">
              Score type: {result.score_type} · Version: {result.model_or_feed_version}
            </p>
          </div>

          <div>
            <h4 className="mb-3 font-semibold">
              Detected Indicators ({result.evidence.length})
            </h4>

            {result.evidence.length === 0 ? (
              <p className="text-sm text-slate-400">
                No indicators detected. This does not guarantee the message is safe.
              </p>
            ) : (
              <ul className="space-y-3">
                {result.evidence.map((item, index) => (
                  <li
                    key={`${item.code}-${index}`}
                    className="rounded-lg border border-slate-700 bg-slate-900/70 p-4"
                  >
                    <strong className="text-sm">{item.code}</strong>
                    <span className="ml-3 text-xs text-amber-300">
                      {item.risk_contribution}
                    </span>

                    <p className="mt-2 text-sm text-slate-400">
                      {item.description}
                    </p>

                    {item.matched_text && (
                      <p className="mt-2 break-words text-xs text-slate-500">
                        Matched text: {item.matched_text}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div>
            <h4 className="mb-3 font-semibold">Recommendations</h4>

            {result.recommendations.length > 0 ? (
              <ul className="list-disc space-y-2 pl-5 text-sm text-slate-400">
                {result.recommendations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-400">
                No recommendations returned.
              </p>
            )}
          </div>

          {result.extracted_urls.length > 0 && (
            <div>
              <h4 className="mb-3 font-semibold">URLs Found in Message</h4>

              <ul className="space-y-2">
                {result.extracted_urls.map((item, index) => (
                  <li
                    key={`${item.url}-${index}`}
                    className="break-all rounded-lg bg-slate-900 p-3 text-sm"
                  >
                    {item.url}

                    <p className="mt-2 text-xs text-slate-500">
                      {item.scan_result
                        ? `URL scan result: ${item.scan_result.label} risk`
                        : 'No URL scan result available'}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.error && (
            <p role="status" className="text-sm text-amber-300">
              {result.error}
            </p>
          )}

          <p className="border-t border-slate-700 pt-4 text-xs text-slate-500">
            {result.limitations}
          </p>
        </section>
      )}
    </div>
  );
}
