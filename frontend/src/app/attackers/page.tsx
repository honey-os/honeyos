'use client';

import React, { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  Users,
  Filter,
  Download,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  X,
  Search,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import SeverityBadge from '@/components/ui/SeverityBadge';
import { formatDate, formatRelativeTime, formatNumber } from '@/utils/formatters';
import { getAttackerEvents } from '@/lib/api';
import type { Event, Attacker } from '@/lib/api';
import clsx from 'clsx';

const PROTOCOLS = ['ssh', 'http', 'https', 'telnet', 'ftp', 'mysql', 'postgresql', 'dns', 'smb'];

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

  const [filters, setFilters] = useState({
    protocol: '',
    search: '',
    sort_by: 'last_seen',
    per_page: 25,
  });

  const searchParams = useSearchParams();
  const [showFilters, setShowFilters] = useState(true);
  const [expandedIP, setExpandedIP] = useState<string | null>(
    searchParams.get('ip')
  );

  const loadAttackers = useCallback(
    (page: number = 1) => {
      fetchAttackers({ ...filters, page });
    },
    [fetchAttackers, filters]
  );

  useEffect(() => {
    loadAttackers(1);
  }, [loadAttackers]);

  const handleFilterChange = (key: string, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({
      protocol: '',
      search: '',
      sort_by: 'last_seen',
      per_page: 25,
    });
  };

  const hasActiveFilters = filters.protocol || filters.search;

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
                value={filters.protocol}
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
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  placeholder="Filter by IP address..."
                  className="input-field w-full pl-9"
                />
              </div>
            </div>
            <div>
              <label className="label-text">Sort By</label>
              <select
                value={filters.sort_by}
                onChange={(e) => handleFilterChange('sort_by', e.target.value)}
                className="select-field w-full"
              >
                <option value="last_seen">Most Recent</option>
                <option value="count">Most Events</option>
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
                    <React.Fragment key={attacker.ip}>
                      <tr
                        className="cursor-pointer hover:bg-[#1c1c28] transition-colors"
                        onClick={() =>
                          setExpandedIP(
                            expandedIP === attacker.ip ? null : attacker.ip
                          )
                        }
                      >
                        <td className="px-4 py-3 text-sm font-mono text-amber-400">
                          {attacker.ip}
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
                          {expandedIP === attacker.ip ? (
                            <ChevronUp className="w-4 h-4" />
                          ) : (
                            <ChevronDown className="w-4 h-4" />
                          )}
                        </td>
                      </tr>

                      {/* Expanded details */}
                      {expandedIP === attacker.ip && (
                        <tr>
                          <td colSpan={8} className="px-4 py-4 bg-[#111118]">
                            <AttackerDetails attacker={attacker} />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
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

// ---------------------------------------------------------------------------
// Attacker detail sub-component
// ---------------------------------------------------------------------------

function AttackerDetails({ attacker }: { attacker: Attacker }) {
  const [events, setEvents] = useState<Event[]>([]);
  const [eventsLoading, setEventsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setEventsLoading(true);
    getAttackerEvents(attacker.ip, { per_page: 10 })
      .then((data) => {
        if (!cancelled) {
          setEvents(data.items || []);
          setEventsLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) setEventsLoading(false);
      });
    return () => { cancelled = true; };
  }, [attacker.ip]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Left: Geo details */}
      <div className="space-y-3">
        <h3 className="text-sm font-medium text-gray-300 mb-2">Geo Details</h3>
        <div className="bg-[#0a0a0f] rounded-lg p-4 space-y-2">
          <DetailRow label="IP Address" value={attacker.ip} mono />
          <DetailRow
            label="Country"
            value={attacker.country ? `${countryFlag(attacker.country_code)} ${attacker.country}` : 'Unknown'}
          />
          <DetailRow label="City" value={attacker.city || 'Unknown'} />
          <DetailRow label="ISP" value={attacker.isp || 'Unknown'} />
          <DetailRow label="Organization" value={attacker.org || 'Unknown'} />
          {attacker.lat != null && attacker.lon != null && (
            <DetailRow
              label="Coordinates"
              value={`${attacker.lat.toFixed(4)}, ${attacker.lon.toFixed(4)}`}
              mono
            />
          )}
          <DetailRow label="Total Events" value={formatNumber(attacker.event_count)} />
          <DetailRow label="First Seen" value={formatDate(attacker.first_seen)} />
          <DetailRow label="Last Seen" value={formatDate(attacker.last_seen)} />
          <div>
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
              Protocols
            </span>
            <div className="flex flex-wrap gap-1 mt-1">
              {attacker.protocols.map((p) => (
                <ProtocolBadge key={p} protocol={p} />
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Right: Recent events */}
      <div className="space-y-3">
        <h3 className="text-sm font-medium text-gray-300 mb-2">Recent Events</h3>
        <div className="bg-[#0a0a0f] rounded-lg overflow-hidden">
          {eventsLoading ? (
            <div className="p-6 text-center">
              <div className="inline-block w-5 h-5 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
              <p className="mt-2 text-xs text-gray-500">Loading events...</p>
            </div>
          ) : events.length === 0 ? (
            <div className="p-6 text-center text-sm text-gray-600">
              No events found
            </div>
          ) : (
            <div className="divide-y divide-[#2a2a3a]/50">
              {events.map((event) => (
                <Link
                  key={event.id}
                  href={`/events?event=${event.id}`}
                  className="px-4 py-3 flex items-center gap-3 hover:bg-[#1c1c28] transition-colors block"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs text-gray-500">
                        {formatDate(event.timestamp, 'MMM d, HH:mm:ss')}
                      </span>
                      <ProtocolBadge protocol={event.protocol} />
                      <SeverityBadge severity={event.severity} />
                    </div>
                    <p className="text-sm text-gray-400 truncate">
                      {event.event_type.replace(/_/g, ' ')}
                      {event.destination_port ? ` :${event.destination_port}` : ''}
                    </p>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
        {label}
      </span>
      <p className={clsx('text-sm text-gray-300 mt-0.5', mono && 'font-mono')}>
        {value}
      </p>
    </div>
  );
}
