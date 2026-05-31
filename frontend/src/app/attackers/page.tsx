'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Filter,
  Download,
  ChevronLeft,
  ChevronRight,
  ChevronRight as ChevronRightIcon,
  X,
  Search,
  ShieldBan,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import { formatDate, formatRelativeTime, formatNumber } from '@/utils/formatters';
import { useUrlFilters } from '@/utils/useUrlFilters';
import clsx from 'clsx';

const PROTOCOLS = ['ssh', 'http', 'https', 'telnet', 'ftp', 'mysql', 'postgresql', 'dns', 'smb', 'rdp'];

export default function AttackersPage() {
  const {
    attackers,
    attackersTotal,
    attackersPage,
    attackersPages,
    attackersLoading,
    attackersError,
    fetchAttackers,
  } = useStore();

  const router = useRouter();
  const { getParam, setParam, clearParams } = useUrlFilters();
  const [showFilters, setShowFilters] = useState(true);

  const filterProtocol = getParam('protocol');
  const filterSearch = getParam('search');
  const filterSortBy = getParam('sort_by') || 'last_seen';

  const loadAttackers = useCallback(
    (page: number = 1) => {
      fetchAttackers({
        page,
        per_page: 25,
        protocol: filterProtocol || undefined,
        search: filterSearch || undefined,
        sort_by: filterSortBy,
      });
    },
    [fetchAttackers, filterProtocol, filterSearch, filterSortBy]
  );

  useEffect(() => {
    loadAttackers(1);
  }, [loadAttackers]);

  const handleFilterChange = (key: string, value: string) => {
    setParam(key, value);
  };

  const clearFilters = () => {
    clearParams();
  };

  const hasActiveFilters = filterProtocol || filterSearch;

  const handleExport = () => {
    const csv = [
      ['IP Address', 'Event Count', 'First Seen', 'Last Seen', 'Protocols', 'Country', 'City', 'Organization', 'ISP'].join(','),
      ...attackers.map((a) =>
        [
          a.ip,
          a.event_count,
          a.first_seen,
          a.last_seen,
          `"${a.protocols.join('; ')}"`,
          a.country || '',
          a.city || '',
          a.org || '',
          a.isp || '',
        ].join(',')
      ),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `honeyos-attackers-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Attackers</h1>
          <p className="text-sm text-gray-500 mt-1">
            {formatNumber(attackersTotal)} unique attacker IPs
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
                value={filterProtocol}
                onChange={(e) => handleFilterChange('protocol', e.target.value)}
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
            <div>
              <label className="label-text">Search IP</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  type="text"
                  value={filterSearch}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  placeholder="Filter by IP address..."
                  className="input-field w-full pl-9"
                />
              </div>
            </div>
            <div>
              <label className="label-text">Sort By</label>
              <select
                value={filterSortBy}
                onChange={(e) => handleFilterChange('sort_by', e.target.value)}
                className="select-field w-full"
              >
                <option value="last_seen">Most Recent</option>
                <option value="count">Most Events</option>
                <option value="blocked">Blocked First</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {attackersError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {attackersError}
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden">
        {attackersLoading && attackers.length === 0 ? (
          <div className="p-12 text-center">
            <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
            <p className="mt-3 text-sm text-gray-500">Loading attackers...</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2a2a3a]">
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    IP Address
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Location
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Organization
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Protocols
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Events
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    First Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Seen
                  </th>
                  <th className="w-8" />
                </tr>
              </thead>
              <tbody className="divide-y divide-[#2a2a3a]/50">
                {attackers.length === 0 ? (
                  <tr>
                    <td
                      colSpan={8}
                      className="px-4 py-12 text-center text-sm text-gray-600"
                    >
                      No attackers match your filters
                    </td>
                  </tr>
                ) : (
                  attackers.map((attacker) => (
                    <tr
                      key={attacker.ip}
                      className="cursor-pointer hover:bg-[#1c1c28] transition-colors"
                      onClick={() => router.push(`/attackers/${attacker.ip}`)}
                    >
                      <td className="px-4 py-3 text-sm font-mono text-amber-400">
                        <div className="flex items-center gap-2">
                          {attacker.ip}
                          {attacker.throttled && attacker.throttled.length > 0 && (
                            <span
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-red-500/15 text-red-400 border border-red-500/30"
                              title={`Blocked on: ${attacker.throttled.map((t) => t.protocol.toUpperCase()).join(', ')}`}
                            >
                              <ShieldBan className="w-3 h-3" />
                              Blocked
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-300 whitespace-nowrap">
                        {attacker.country ? (
                          <>
                            {countryFlag(attacker.country_code)} {attacker.country}
                            {attacker.city ? `, ${attacker.city}` : ''}
                          </>
                        ) : (
                          <span className="text-gray-600">Unknown</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400 max-w-[200px] truncate">
                        {attacker.org || <span className="text-gray-600">-</span>}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {attacker.protocols.map((p) => (
                            <ProtocolBadge key={p} protocol={p} />
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm font-mono text-gray-300">
                        {formatNumber(attacker.event_count)}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400 whitespace-nowrap">
                        {formatDate(attacker.first_seen, 'MMM d, yyyy')}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400 whitespace-nowrap">
                        {formatRelativeTime(attacker.last_seen)}
                      </td>
                      <td className="px-4 py-2 text-gray-500">
                        <ChevronRightIcon className="w-4 h-4" />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {attackersPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-500">
            Page {attackersPage} of {attackersPages} ({formatNumber(attackersTotal)} total)
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => loadAttackers(attackersPage - 1)}
              disabled={attackersPage <= 1}
              className="btn-secondary flex items-center gap-1 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
              Previous
            </button>
            <button
              onClick={() => loadAttackers(attackersPage + 1)}
              disabled={attackersPage >= attackersPages}
              className="btn-secondary flex items-center gap-1 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function countryFlag(code?: string | null): string {
  if (!code || code.length !== 2) return '';
  const offset = 0x1F1E6 - 65;
  return String.fromCodePoint(
    code.codePointAt(0)! + offset,
    code.codePointAt(1)! + offset,
  );
}
