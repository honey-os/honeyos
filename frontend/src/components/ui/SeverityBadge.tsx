'use client';

import React from 'react';
import clsx from 'clsx';

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

const severityConfig: Record<string, { bg: string; text: string; dot: string }> = {
  critical: {
    bg: 'bg-red-500/15 border-red-500/30',
    text: 'text-red-400',
    dot: 'bg-red-500',
  },
  high: {
    bg: 'bg-orange-500/15 border-orange-500/30',
    text: 'text-orange-400',
    dot: 'bg-orange-500',
  },
  medium: {
    bg: 'bg-yellow-500/15 border-yellow-500/30',
    text: 'text-yellow-400',
    dot: 'bg-yellow-500',
  },
  low: {
    bg: 'bg-green-500/15 border-green-500/30',
    text: 'text-green-400',
    dot: 'bg-green-500',
  },
  info: {
    bg: 'bg-blue-500/15 border-blue-500/30',
    text: 'text-blue-400',
    dot: 'bg-blue-500',
  },
};

export default function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const config = severityConfig[severity.toLowerCase()] || severityConfig.medium;

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border',
        config.bg,
        config.text,
        className
      )}
    >
      <span className={clsx('w-1.5 h-1.5 rounded-full', config.dot)} />
      {severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase()}
    </span>
  );
}
