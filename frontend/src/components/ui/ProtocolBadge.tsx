'use client';

import React from 'react';
import clsx from 'clsx';

interface ProtocolBadgeProps {
  protocol: string;
  className?: string;
}

const protocolConfig: Record<string, { bg: string; text: string }> = {
  ssh: { bg: 'bg-emerald-500/15 border-emerald-500/30', text: 'text-emerald-400' },
  http: { bg: 'bg-blue-500/15 border-blue-500/30', text: 'text-blue-400' },
  https: { bg: 'bg-blue-500/15 border-blue-500/30', text: 'text-blue-400' },
  telnet: { bg: 'bg-purple-500/15 border-purple-500/30', text: 'text-purple-400' },
  ftp: { bg: 'bg-cyan-500/15 border-cyan-500/30', text: 'text-cyan-400' },
  mysql: { bg: 'bg-orange-500/15 border-orange-500/30', text: 'text-orange-400' },
  smb: { bg: 'bg-rose-500/15 border-rose-500/30', text: 'text-rose-400' },
  rdp: { bg: 'bg-indigo-500/15 border-indigo-500/30', text: 'text-indigo-400' },
  dns: { bg: 'bg-teal-500/15 border-teal-500/30', text: 'text-teal-400' },
  smtp: { bg: 'bg-pink-500/15 border-pink-500/30', text: 'text-pink-400' },
};

const defaultConfig = { bg: 'bg-gray-500/15 border-gray-500/30', text: 'text-gray-400' };

export default function ProtocolBadge({ protocol, className }: ProtocolBadgeProps) {
  const config = protocolConfig[protocol.toLowerCase()] || defaultConfig;

  return (
    <span
      className={clsx(
        'inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-mono font-medium border uppercase tracking-wider',
        config.bg,
        config.text,
        className
      )}
    >
      {protocol}
    </span>
  );
}
