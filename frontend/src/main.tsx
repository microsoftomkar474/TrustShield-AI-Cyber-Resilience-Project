import { StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import URLAnalysisPage from './pages/URLAnalysisPage';
import MessageAnalysisPage from './pages/MessageAnalysisPage';
import './index.css';

type ActivePage = 'url' | 'message';

function App() {
  const [activePage, setActivePage] = useState<ActivePage>('url');

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-5">
        <div className="mx-auto max-w-7xl">
          <h1 className="text-2xl font-bold">TrustShield AI</h1>
          <p className="mt-1 text-sm text-slate-400">
            Cyber Resilience — Phishing Detection
          </p>

          <nav
            className="mt-5 flex flex-wrap gap-3"
            aria-label="Analysis modules"
          >
            <button
              type="button"
              onClick={() => setActivePage('url')}
              aria-current={activePage === 'url' ? 'page' : undefined}
              className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                activePage === 'url'
                  ? 'bg-blue-600 text-white'
                  : 'border border-slate-700 text-slate-300 hover:bg-slate-800'
              }`}
            >
              URL Phishing Analysis
            </button>

            <button
              type="button"
              onClick={() => setActivePage('message')}
              aria-current={activePage === 'message' ? 'page' : undefined}
              className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                activePage === 'message'
                  ? 'bg-blue-600 text-white'
                  : 'border border-slate-700 text-slate-300 hover:bg-slate-800'
              }`}
            >
              Message Phishing Analysis
            </button>
          </nav>
        </div>
      </header>

      <section className="mx-auto max-w-7xl px-6 py-8">
        {activePage === 'url' ? (
          <URLAnalysisPage />
        ) : (
          <MessageAnalysisPage />
        )}
      </section>
    </main>
  );
}

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Root element not found in index.html');
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>
);
