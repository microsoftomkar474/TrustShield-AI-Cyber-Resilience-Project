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
      <section className="glass-panel p-6">
        <h2 className="text-xl font-bold text-slate-100 mb-2">
          Suspicious Message Analysis
        </h2>

        <p className="text-sm text-slate-400 mb-5">
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
            maxLength={MAX_MESSAGE_LENGTH}
            rows={6}
            placeholder="Paste the suspicious message here..."
            className="w-full rounded-xl border border-slate-700 bg-slate-900 p-3 text-slate-100 placeholder:text-slate-500 focus:border-shield-accent focus:outline-none"
            aria-describedby="message-help"
          />

          <div
            id="message-help"
            className="text-right text-xs text-slate-500"
          >
            {message.length}/{MAX_MESSAGE_LENGTH} characters
          </div>

          {message.length > 0 && !isValid && (
            <p className="text-sm text-amber-300" role="alert">
              Enter a valid message within the character limit.
            </p>
          )}

          <div className="flex flex-wrap gap-3">
            <button
              type="submit"
              disabled={!isValid || state.status === 'loading'}
              className="flex-1 rounded-xl bg-blue-600 px-5 py-3 font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {state.status === 'loading'
                ? 'Analysing message...'
                : 'Analyse Message'}
            </button>

            <button
              type="button"
              onClick={handleReset}
              className="rounded-xl border border-slate-700 px-5 py-3 text-slate-300 hover:bg-slate-800"
            >
              Reset
            </button>
          </div>
        </form>
      </section>

      {state.status === 'loading' && (
        <section className="glass-panel p-6" role="status">
          <p className="text-slate-300">
            Analysing message for phishing indicators. Please wait...
          </p>
        </section>
      )}

      {state.status === 'error' && (
        <section
          className="glass-panel border border-red-500/40 p-6"
          role="alert"
        >
          <h3 className="font-semibold text-red-300 mb-2">
            Analysis failed
          </h3>
          <p className="text-sm text-slate-300">
            {state.errorMessage}
          </p>
        </section>
      )}

      {result && state.status === 'success' && (
        <section className="glass-panel p-6 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-lg font-bold text-slate-100">
                Analysis Result
              </h3>
              <p className="mt-1 text-sm text-slate-400">
                {result.message_preview}
              </p>
            </div>
            <RiskBadge level={result.label} />
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
              Score type: {result.score_type} · Version:{' '}
              {result.model_or_feed_version}
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-slate-100 mb-3">
              Detected Indicators ({result.evidence.length})
            </h4>

            {result.evidence.length > 0 ? (
              <IndicatorList indicators={result.evidence} />
            ) : (
              <p className="text-sm text-slate-400">
                No indicators detected. This does not guarantee the message
                is safe.
              </p>
            )}
          </div>

          {result.extracted_urls.length > 0 && (
            <div>
              <h4 className="font-semibold text-slate-100 mb-3">
                URLs Found in Message
              </h4>

              <ul className="space-y-3">
                {result.extracted_urls.map((item, index) => (
                  <li
                    key={`${item.url}-${index}`}
                    className="rounded-lg border border-slate-700 p-3"
                  >
                    <p className="break-all text-sm text-slate-200">
                      {item.url}
                    </p>

                    {item.scan_result ? (
                      <p className="mt-2 text-sm text-slate-400">
                        URL scan result: {item.scan_result.label} RISK
                        {' · '}
                        {(item.scan_result.score * 100).toFixed(1)}%
                      </p>
                    ) : (
                      <p className="mt-2 text-xs text-slate-500">
                        No URL scan result available.
                      </p>
                    )}
                  </li>
                ))}
              </ul>

              <p className="mt-2 text-xs text-slate-500">
                URLs are displayed for inspection and are not opened
                automatically.
              </p>
            </div>
          )}

          {result.recommendations.length > 0 && (
            <div>
              <h4 className="font-semibold text-slate-100 mb-3">
                Recommendations
              </h4>

              <ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">
                {result.recommendations.map((recommendation, index) => (
                  <li key={index}>{recommendation}</li>
                ))}
              </ul>
            </div>
          )}

          {result.limitations && (
            <div className="border-t border-slate-700 pt-4">
              <h4 className="font-semibold text-slate-300 mb-2">
                Limitations
              </h4>
              <p className="text-xs leading-relaxed text-slate-400">
                {result.limitations}
              </p>
            </div>
          )}

          {result.error && (
            <p className="text-sm text-amber-300" role="status">
              Note: {result.error}
            </p>
          )}
        </section>
      )}
    </main>
  );
}

