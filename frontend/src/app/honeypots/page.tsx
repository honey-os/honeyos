'use client';

import React, { useEffect } from 'react';
import {
  Server,
  Terminal,
  Globe,
  Database,
  Monitor,
  Network,
  HardDrive,
  Wifi,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import type { Honeypot } from '@/lib/api';
import { formatRelativeTime, formatNumber } from '@/utils/formatters';
import clsx from 'clsx';

const protocolIcons: Record<string, React.ElementType> = {
  ssh: Terminal,
  http: Globe,
  https: Globe,
  telnet: Monitor,
  ftp: HardDrive,
  mysql: Database,
  smb: Network,
  rdp: Monitor,
  dns: Wifi,
};

const protocolColors: Record<string, string> = {
  ssh: 'text-emerald-400 bg-emerald-500/10',
  http: 'text-blue-400 bg-blue-500/10',
  https: 'text-blue-400 bg-blue-500/10',
  telnet: 'text-purple-400 bg-purple-500/10',
  ftp: 'text-cyan-400 bg-cyan-500/10',
  mysql: 'text-orange-400 bg-orange-500/10',
  smb: 'text-rose-400 bg-rose-500/10',
  rdp: 'text-indigo-400 bg-indigo-500/10',
  dns: 'text-teal-400 bg-teal-500/10',
};

export default function HoneypotsPage() {
  const {
    honeypots,
    honeypotsLoading,
    honeypotsError,
    fetchHoneypots,
  } = useStore();

  useEffect(() => {
    fetchHoneypots();
  }, [fetchHoneypots]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Honeypots</h1>
          <p className="text-sm text-gray-500 mt-1">
            Manage your deception services
          </p>
        </div>
      </div>

      {/* Error */}
      {honeypotsError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {honeypotsError}
        </div>
      )}

      {/* Loading */}
      {honeypotsLoading && honeypots.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="mt-3 text-sm text-gray-500">Loading honeypots...</p>
        </div>
      ) : honeypots.length === 0 ? (
        <div className="card p-12 text-center">
          <Server className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400 mb-2">
            No honeypots configured
          </h3>
          <p className="text-sm text-gray-600">
            Deploy your first deception service to start catching intruders.
          </p>
        </div>
      ) : (
        /* Honeypot grid */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {honeypots.map((honeypot) => {
            const IconComp =
              protocolIcons[honeypot.protocol.toLowerCase()] || Server;
            const colorClass =
              protocolColors[honeypot.protocol.toLowerCase()] ||
              'text-gray-400 bg-gray-500/10';

            return (
              <div
                key={honeypot.id}
                className={clsx(
                  'card p-5 relative group transition-all duration-300',
                  honeypot.enabled
                    ? 'border-[#2a2a3a] hover:border-amber-500/20'
                    : 'border-[#2a2a3a]/50 opacity-60'
                )}
              >
                {/* Status indicator */}
                <div className="absolute top-4 right-4">
                  <span
                    className={clsx(
                      'inline-block w-2.5 h-2.5 rounded-full',
                      honeypot.enabled ? 'bg-green-400' : 'bg-gray-600'
                    )}
                    title={honeypot.enabled ? 'Active' : 'Disabled'}
                  />
                </div>

                {/* Protocol icon & name */}
                <div className="flex items-center gap-3 mb-4">
                  <div
                    className={clsx(
                      'w-12 h-12 rounded-lg flex items-center justify-center',
                      colorClass
                    )}
                  >
                    <IconComp className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-100">
                      {honeypot.name}
                    </h3>
                    <span className="text-xs font-mono text-gray-500 uppercase">
                      {honeypot.protocol}
                    </span>
                  </div>
                </div>

                {/* Info */}
                <div className="space-y-2 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Port</span>
                    <span className="font-mono text-gray-300">
                      {honeypot.port}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Status</span>
                    <span
                      className={
                        honeypot.enabled ? 'text-green-400' : 'text-gray-600'
                      }
                    >
                      {honeypot.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Interactions</span>
                    <span className="font-mono text-gray-300">
                      {formatNumber(honeypot.total_interactions)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Last Activity</span>
                    <span className="text-gray-400 text-xs">
                      {honeypot.last_activity
                        ? formatRelativeTime(honeypot.last_activity)
                        : 'Never'}
                    </span>
                  </div>
                </div>

                {honeypot.description && (
                  <p className="text-xs text-gray-600 mt-3 border-t border-[#2a2a3a] pt-3">
                    {honeypot.description}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
