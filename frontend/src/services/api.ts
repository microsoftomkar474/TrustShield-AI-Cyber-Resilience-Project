/**
 * TrustShield AI — Cyber Resilience
 * API service layer
 *
 * Handles all HTTP communication with the FastAPI backend.
 * Uses axios for requests with sensible timeout and error handling.
 *
 * Security note:
 * - Never constructs HTTP requests to the analysed URLs
 * - Only posts URL strings to the backend analysis endpoint
 * - Input validation is done server-side via Pydantic
 */

import axios, { AxiosError } from 'axios';
import type { URLScanResponse, MessageScanResponse } from '../types/api';

// Backend base URL — in development, Vite proxies /api to localhost:8000
const API_BASE = '/api/v1/cyber';

const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000, // 30 seconds — allows for TI lookups
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Submit a URL for phishing analysis.
 *
 * SECURITY: This sends the URL as a string in a JSON request body.
 * The browser never navigates to or fetches the URL itself.
 */
export async function analyseURL(url: string): Promise<URLScanResponse> {
  try {
    const response = await apiClient.post<URLScanResponse>('/url-scans', { url });
    return response.data;
  } catch (error) {
    throw extractError(error, 'URL analysis failed');
  }
}

/**
 * Submit a message for phishing analysis.
 */
export async function analyseMessage(message: string): Promise<MessageScanResponse> {
  try {
    const response = await apiClient.post<MessageScanResponse>('/message-scans', { message });
    return response.data;
  } catch (error) {
    throw extractError(error, 'Message analysis failed');
  }
}

/**
 * Check backend health.
 * Used to show connection status in the dashboard.
 */
export async function checkHealth(): Promise<boolean> {
  try {
    await axios.get('/health', { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Extract a human-readable error message from an axios error.
 */
function extractError(error: unknown, fallback: string): Error {
  if (error instanceof AxiosError) {
    if (error.response) {
      // Server returned an error response
      const detail = error.response.data?.detail || error.response.data?.error;
      if (detail) {
        if (Array.isArray(detail)) {
          // Pydantic validation errors
          const messages = detail.map((d: { msg: string }) => d.msg).join('; ');
          return new Error(`Validation error: ${messages}`);
        }
        return new Error(String(detail));
      }
      return new Error(`Server error (${error.response.status}): ${error.response.statusText}`);
    } else if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      return new Error('Request timed out. The backend may be busy. Please try again.');
    } else if (error.code === 'ERR_NETWORK' || !error.response) {
      return new Error(
        'Cannot reach the backend server. ' +
        'Ensure the FastAPI backend is running on http://localhost:8000.'
      );
    }
  }
  return new Error(fallback);
}
