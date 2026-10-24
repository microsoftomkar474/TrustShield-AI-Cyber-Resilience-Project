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
    className: 'risk-badge-low',
    icon: '✓',
    label: 'LOW RISK',
    glow: 'shadow-glow-green',
  },
  MEDIUM: {
    className: 'risk-badge-medium',
    icon: '⚠',
    label: 'MEDIUM RISK',
    glow: 'shadow-glow-amber',
  },
  HIGH: {
    className: 'risk-badge-high',
    icon: '✕',
    label: 'HIGH RISK',
    glow: 'shadow-glow-red',
  },
};

export default function RiskBadge({ level, size = 'md' }: RiskBadgeProps) {
  const config = RISK_CONFIG[level];
  const sizeClass = size === 'lg'
    ? 'text-base px-4 py-2 rounded-xl'
    : size === 'sm'
    ? 'text-xs px-2 py-0.5'
    : '';

  return (
    <span className={`${config.className} ${sizeClass} ${config.glow}`}>
      <span aria-hidden="true">{config.icon}</span>
      {config.label}
    </span>
  );
}
