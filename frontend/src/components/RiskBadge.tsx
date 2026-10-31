/**
 * RiskBadge — displays LOW / MEDIUM / HIGH risk classification
 * with colour-coded styling and an icon.
 */

import type { RiskLevel } from '../types/api';

interface RiskBadgeProps {
  level: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
}

const RISK_CONFIG = {
  LOW: {
    className: 'risk-badge-low bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
    icon: '✓',
    label: 'LOW RISK',
    glow: 'shadow-glow-green',
  },
  MEDIUM: {
    className: 'risk-badge-medium bg-amber-500/15 text-amber-400 border border-amber-500/30',
    icon: '⚠',
    label: 'MEDIUM RISK',
    glow: 'shadow-glow-amber',
  },
  HIGH: {
    className: 'risk-badge-high bg-red-500/15 text-red-400 border border-red-500/30',
    icon: '✕',
    label: 'HIGH RISK',
    glow: 'shadow-glow-red',
  },
  UNKNOWN: {
    className: 'risk-badge-unknown bg-slate-500/20 text-slate-300 border border-slate-500/40',
    icon: '?',
    label: 'UNKNOWN / INCONCLUSIVE',
    glow: 'shadow-glow-blue',
  },
};

export default function RiskBadge({ level, size = 'md' }: RiskBadgeProps) {
  const config = RISK_CONFIG[level] || RISK_CONFIG.UNKNOWN;
  const sizeClass = size === 'lg'
    ? 'text-base px-4 py-2 rounded-xl'
    : size === 'sm'
    ? 'text-xs px-2 py-0.5'
    : '';

  return (
    <span className={`inline-flex items-center gap-1.5 font-semibold rounded-lg ${config.className} ${sizeClass} ${config.glow}`}>
      <span aria-hidden="true">{config.icon}</span>
      {config.label}
    </span>
  );
}
