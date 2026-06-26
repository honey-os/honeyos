'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  KeyRound,
  Filter,
  Download,
  X,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import { formatNumber } from '@/utils/formatters';
import { useUrlFilters } from '@/utils/useUrlFilters';
import clsx from 'clsx';

const PROTOCOLS = ['ssh', 'telnet', 'ftp', 'mysql', 'postgresql', 'smb', 'rdp'];

export default function CredentialsPage() {
  const {
    credentials,
    credentialsLoading,
    credentialsError,
    fetchCredentials,
  } = useStore();

  const { getParam, setParam, clearParams } = useUrlFilters();
  const protocol = getParam('protocol');
  const [showFilters, setShowFilters] = useState(true);

  const loadCredentials = useCallback(() => {
    fetchCredentials(protocol ? { protocol } : {});
  }, [fetchCredentials, protocol]);

  useEffect(() => {
    loadCredentials();
  }, [loadCredentials]);

  const clearFilters = () => {
    clearParams();
  };

  const hasActiveFilters = !!protocol;

  const handleExport = () => {
    if (!credentials) return;

    const sections: string[] = [];

    // Usernames section
    sections.push('--- Top Usernames ---');
    sections.push(['Rank', 'Username', 'Count', 'Protocols'].join(','));
    credentials.top_usernames.forEach((u, i) => {
      sections.push(
        [i + 1, `"${u.username}"`, u.count, `"${u.protocols.join('; ')}"`].join(',')
      );
    });

    sections.push('');

    // Passwords section
    sections.push('--- Top Passwords ---');
    sections.push(['Rank', 'Password', 'Count'].join(','));
    credentials.top_passwords.forEach((p, i) => {
      sections.push([i + 1, `"${p.password}"`, p.count].join(','));
    });

    sections.push('');

    // Combos section
    sections.push('--- Top Combinations ---');
    sections.push(['Rank', 'Username', 'Password', 'Count', 'Protocols'].join(','));
    credentials.top_combos.forEach((c, i) => {
      sections.push(
        [i + 1, `"${c.username}"`, `"${c.password}"`, c.count, `"${c.protocols.join('; ')}"`].join(',')
      );
    });

    const blob = new Blob([sections.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `honeyos-credentials-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Credentials</h1>
          <p className="text-sm text-gray-500 mt-1">
            {formatNumber(credentials?.total_attempts ?? 0)} total authentication attempts
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={clsx(
              'btn-secondary flex items-center gap-2 text-sm',
              showFilters && 'border-amber-500/30 text-amber-400'
            )}
          >
            <Filter className="w-4 h-4" />
            Filters
          </button>
          <button
            onClick={handleExport}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="card p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-gray-300">Filters</span>
            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="text-xs text-gray-500 hover:text-amber-400 flex items-center gap-1 transition-colors"
              >
                <X className="w-3 h-3" />
                Clear all
              </button>
            )}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <div>
              <label className="label-text">Protocol</label>
              <select
                value={protocol}
                onChange={(e) => setParam('protocol', e.target.value)}
                className="select-field w-full"
              >
                <option value="">All protocols</option>
                {PROTOCOLS.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {credentialsError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {credentialsError}
        </div>
      )}

      {/* Loading */}
      {credentialsLoading && !credentials ? (
        <div className="card p-12 text-center">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="mt-3 text-sm text-gray-500">Loading credentials...</p>
        </div>
      ) : credentials ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Top Usernames */}
          <div className="card overflow-hidden">
            <div className="px-4 py-3 border-b border-[#2a2a3a]">
              <h2 className="text-sm font-medium text-gray-300">
                Top Usernames
                <span className="ml-2 text-xs text-gray-500">
                  ({formatNumber(credentials.top_usernames.length)})
                </span>
              </h2>
            </div>
            <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-[#111118]">
                  <tr className="border-b border-[#2a2a3a]">
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-12">
                      #
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Username
                    </th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase tracking-wider w-20">
                      Count
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2a2a3a]/50">
                  {credentials.top_usernames.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="px-4 py-8 text-center text-sm text-gray-600">
                        No usernames captured
                      </td>
                    </tr>
                  ) : (
                    credentials.top_usernames.map((u, i) => (
                      <tr key={u.username} className="hover:bg-[#1c1c28] transition-colors">
                        <td className="px-4 py-2 text-sm text-gray-500">{i + 1}</td>
                        <td className="px-4 py-2">
                          <div className="text-sm font-mono text-amber-400">{u.username}</div>
                          {u.protocols.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {u.protocols.map((p) => (
                                <ProtocolBadge key={p} protocol={p} />
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-2 text-sm font-mono text-gray-300 text-right">
                          {formatNumber(u.count)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Top Passwords */}
          <div className="card overflow-hidden">
            <div className="px-4 py-3 border-b border-[#2a2a3a]">
              <h2 className="text-sm font-medium text-gray-300">
                Top Passwords
                <span className="ml-2 text-xs text-gray-500">
                  ({formatNumber(credentials.top_passwords.length)})
                </span>
              </h2>
            </div>
            <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-[#111118]">
                  <tr className="border-b border-[#2a2a3a]">
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-12">
                      #
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Password
                    </th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase tracking-wider w-20">
                      Count
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2a2a3a]/50">
                  {credentials.top_passwords.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="px-4 py-8 text-center text-sm text-gray-600">
                        No passwords captured
                      </td>
                    </tr>
                  ) : (
                    credentials.top_passwords.map((p, i) => (
                      <tr key={p.password} className="hover:bg-[#1c1c28] transition-colors">
                        <td className="px-4 py-2 text-sm text-gray-500">{i + 1}</td>
                        <td className="px-4 py-2 text-sm font-mono text-amber-400">{p.password}</td>
                        <td className="px-4 py-2 text-sm font-mono text-gray-300 text-right">
                          {formatNumber(p.count)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Top Combinations — full width */}
          <div className="card overflow-hidden lg:col-span-2">
            <div className="px-4 py-3 border-b border-[#2a2a3a]">
              <h2 className="text-sm font-medium text-gray-300">
                Top Combinations
                <span className="ml-2 text-xs text-gray-500">
                  ({formatNumber(credentials.top_combos.length)})
                </span>
              </h2>
            </div>
            <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-[#111118]">
                  <tr className="border-b border-[#2a2a3a]">
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-12">
                      #
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Username
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Password
                    </th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase tracking-wider w-20">
                      Count
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2a2a3a]/50">
                  {credentials.top_combos.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-sm text-gray-600">
                        No credential combinations captured
                      </td>
                    </tr>
                  ) : (
                    credentials.top_combos.map((c, i) => (
                      <tr
                        key={`${c.username}:${c.password}`}
                        className="hover:bg-[#1c1c28] transition-colors"
                      >
                        <td className="px-4 py-2 text-sm text-gray-500">{i + 1}</td>
                        <td className="px-4 py-2">
                          <div className="text-sm font-mono text-amber-400">{c.username}</div>
                          {c.protocols.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {c.protocols.map((p) => (
                                <ProtocolBadge key={p} protocol={p} />
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-2 text-sm font-mono text-amber-400">{c.password}</td>
                        <td className="px-4 py-2 text-sm font-mono text-gray-300 text-right">
                          {formatNumber(c.count)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
