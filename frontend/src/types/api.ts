/**
 * TrustShield AI — Cyber Resilience
 * TypeScript type definitions matching the backend Pydantic schemas.
 *
 * These types must stay in sync with:
 *   backend/app/schemas/cyber_schemas.py
 */

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type ScoreType = 'rule_based' | 'threat_intel_confirmed' | 'mock';

// --- URL Scan ---

export interface URLIndicator {
  code: string;
  description: string;
  risk_contribution: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface ThreatIntelResult {
  source: string;
  found: boolean;
  status: string | null;
  queried_at: string | null;
  error: string | null;
  is_mock: boolean;
}

export interface URLScanResponse {
  status: string;
  module: string;
  label: RiskLevel;
  score: number;
  score_type: ScoreType;
  evidence: URLIndicator[];
  model_or_feed_version: string;
  limitations: string;
  url_analysed: string;
  parsed_components: Record<string, string | number | null>;
  threat_intelligence: ThreatIntelResult[];
  recommendations: string[];
  error: string | null;
}

// --- Message Scan ---

export interface MessageIndicator {
  code: string;
  description: string;
  matched_text: string | null;
  risk_contribution: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface ExtractedURL {
  url: string;
  scan_result: URLScanResponse | null;
}

export interface MessageScanResponse {
  status: string;
  module: string;
  label: RiskLevel;
  score: number;
  score_type: ScoreType;
  evidence: MessageIndicator[];
  model_or_feed_version: string;
  limitations: string;
  message_preview: string;
  extracted_urls: ExtractedURL[];
  recommendations: string[];
  error: string | null;
}

// --- API State ---

export type ApiStatus = 'idle' | 'loading' | 'success' | 'error';

export interface AnalysisState<T> {
  status: ApiStatus;
  data: T | null;
  errorMessage: string | null;
}
