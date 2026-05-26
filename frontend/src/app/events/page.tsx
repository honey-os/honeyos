'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Activity,
  Filter,
  Download,
  ChevronLeft,
  ChevronRight,
  X,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import SeverityBadge from '@/components/ui/SeverityBadge';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import { formatDate, formatRelativeTime, truncateText } from '@/utils/formatters';
import { getEvent } from '@/lib/api';
import type { Event } from '@/lib/api';
import clsx from 'clsx';

const EVENT_TYPES = [
  'connection',
  'login_attempt',
  'command',
  'file_transfer',
  'scan',
  'brute_force',
];

const PROTOCOLS = ['ssh', 'http', 'https', 'telnet', 'ftp', 'mysql', 'postgresql', 'smb', 'rdp', 'dns'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export default function EventsPage() {
  const {
    events,
    eventsTotal,
    eventsPage,
    eventsPages,
    eventsLoading,
    eventsError,
    fetchEvents,
  } = useStore();

  const [filters, setFilters] = useState({
    event_type: '',
    protocol: '',
    severity: '',
    start_date: '',
    end_date: '',
    per_page: 25,
  });

  const searchParams = useSearchParams();
  const linkedEventId = searchParams.get('event');
  const [expandedEvent, setExpandedEvent] = useState<string | null>(linkedEventId);
  const [linkedEvent, setLinkedEvent] = useState<Event | null>(null);
  const [showFilters, setShowFilters] = useState(true);

  const loadEvents = useCallback(
    (page: number = 1) => {
      fetchEvents({ ...filters, page });
    },
    [fetchEvents, filters]
  );

  useEffect(() => {
    loadEvents(1);
  }, [loadEvents]);

  // Fetch the specific linked event so it displays even if not on the current page
  useEffect(() => {
    if (!linkedEventId) {
      setLinkedEvent(null);
      return;
    }
    getEvent(linkedEventId)
      .then((e) => setLinkedEvent(e))
      .catch(() => setLinkedEvent(null));
  }, [linkedEventId]);

  const handleFilterChange = (key: string, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({
      event_type: '',
      protocol: '',
      severity: '',
      start_date: '',
      end_date: '',
      per_page: 25,
    });
  };

  const hasActiveFilters = filters.event_type || filters.protocol || filters.severity || filters.start_date || filters.end_date;

  const handleExport = () => {
    const csv = [
      ['Time', 'Type', 'Protocol', 'Source IP', 'Port', 'Severity', 'Details'].join(','),
      ...events.map((e) =>
        [
          e.timestamp,
          e.event_type,
          e.protocol,
          e.source_ip,
          e.destination_port,
          e.severity,
          JSON.stringify(e.details || ''),
        ].join(',')
      ),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `honeyos-events-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Events</h1>
          <p className="text-sm text-gray-500 mt-1">
            {eventsTotal} total events recorded
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
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <div>
              <label className="label-text">Event Type</label>
              <select
                value={filters.event_type}
                onChange={(e) => handleFilterChange('event_type', e.target.value)}
                className="select-field w-full"
              >
                <option value="">All types</option>
                {EVENT_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t.replace('_', ' ')}
                  </option>
                ))}
              </select>
            </div>
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
              <label className="label-text">Severity</label>
              <select
                value={filters.severity}
                onChange={(e) => handleFilterChange('severity', e.target.value)}
                className="select-field w-full"
              >
                <option value="">All severities</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="label-text">Start Date</label>
              <input
                type="date"
                value={filters.start_date}
                onChange={(e) => handleFilterChange('start_date', e.target.value)}
                className="input-field w-full"
              />
            </div>
            <div>
              <label className="label-text">End Date</label>
              <input
                type="date"
                value={filters.end_date}
                onChange={(e) => handleFilterChange('end_date', e.target.value)}
                className="input-field w-full"
              />
            </div>
          </div>
        </div>
      )}

      {/* Error */}
      {eventsError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {eventsError}
        </div>
      )}

      {/* Linked event (from ?event=id, when not on the current page) */}
      {linkedEvent && !events.some((e) => e.id === linkedEvent.id) && (
        <div className="card overflow-hidden border-amber-500/20">
          <div className="px-4 py-2 bg-amber-500/5 border-b border-amber-500/20">
            <span className="text-xs font-medium text-amber-400">Linked Event</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <tbody>
                <tr
                  className="cursor-pointer hover:bg-[#1c1c28] transition-colors"
                  onClick={() =>
                    setExpandedEvent(
                      expandedEvent === linkedEvent.id ? null : linkedEvent.id
                    )
                  }
                >
                  <td className="px-4 py-3 text-sm text-gray-400 whitespace-nowrap">
                    {formatDate(linkedEvent.timestamp, 'MMM d, HH:mm:ss')}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-300">
                    {linkedEvent.event_type.replace('_', ' ')}
                  </td>
                  <td className="px-4 py-3">
                    <ProtocolBadge protocol={linkedEvent.protocol} />
                  </td>
                  <td className="px-4 py-3 text-sm font-mono text-amber-400">
                    {linkedEvent.source_ip}
                  </td>
                  <td className="px-4 py-3 text-sm font-mono text-gray-400">
                    {linkedEvent.destination_port || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={linkedEvent.severity} />
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 max-w-xs truncate">
                    {linkedEvent.details
                      ? truncateText(JSON.stringify(linkedEvent.details), 60)
                      : '-'}
                  </td>
                </tr>
                {expandedEvent === linkedEvent.id && (
                  <tr>
                    <td colSpan={7} className="px-4 py-4 bg-[#111118]">
                      <EventDetails event={linkedEvent} />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden">
        {eventsLoading && events.length === 0 ? (
          <div className="p-12 text-center">
            <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
            <p className="mt-3 text-sm text-gray-500">Loading events...</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2a2a3a]">
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Protocol
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Source IP
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Port
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#2a2a3a]/50">
                {events.length === 0 ? (
                  <tr>
                    <td
                      colSpan={7}
                      className="px-4 py-12 text-center text-sm text-gray-600"
                    >
                      No events match your filters
                    </td>
                  </tr>
                ) : (
                  events.map((event) => (
                    <React.Fragment key={event.id}>
                      <tr
                        className="cursor-pointer hover:bg-[#1c1c28] transition-colors"
                        onClick={() =>
                          setExpandedEvent(
                            expandedEvent === event.id ? null : event.id
                          )
                        }
                      >
                        <td className="px-4 py-3 text-sm text-gray-400 whitespace-nowrap">
                          {formatDate(event.timestamp, 'MMM d, HH:mm:ss')}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-300">
                          {event.event_type.replace('_', ' ')}
                        </td>
                        <td className="px-4 py-3">
                          <ProtocolBadge protocol={event.protocol} />
                        </td>
                        <td className="px-4 py-3 text-sm font-mono text-amber-400">
                          {event.source_ip}
                        </td>
                        <td className="px-4 py-3 text-sm font-mono text-gray-400">
                          {event.destination_port || '-'}
                        </td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={event.severity} />
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500 max-w-xs truncate">
                          {event.details
                            ? truncateText(JSON.stringify(event.details), 60)
                            : '-'}
                        </td>
                      </tr>

                      {/* Expanded details */}
                      {expandedEvent === event.id && (
                        <tr>
                          <td colSpan={7} className="px-4 py-4 bg-[#111118]">
                            <EventDetails event={event} />
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
      {eventsPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-500">
            Page {eventsPage} of {eventsPages} ({eventsTotal} total)
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => loadEvents(eventsPage - 1)}
              disabled={eventsPage <= 1}
              className="btn-secondary flex items-center gap-1 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
              Previous
            </button>
            <button
              onClick={() => loadEvents(eventsPage + 1)}
              disabled={eventsPage >= eventsPages}
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
// Event details sub-component
// ---------------------------------------------------------------------------

function EventDetails({ event }: { event: Event }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div className="space-y-3">
        <DetailRow label="Event ID" value={event.id} mono />
        <DetailRow label="Event Type" value={event.event_type} />
        <DetailRow label="Protocol" value={event.protocol.toUpperCase()} />
        <DetailRow label="Source IP" value={event.source_ip} mono />
        <DetailRow label="Source Port" value={event.source_port?.toString() || 'N/A'} mono />
        <DetailRow label="Destination Port" value={event.destination_port?.toString() || 'N/A'} mono />
        <DetailRow label="Timestamp" value={formatDate(event.timestamp)} />
        {event.session_id && (
          <DetailRow label="Session ID" value={event.session_id} mono />
        )}
        {event.user_agent && (
          <DetailRow label="User Agent" value={event.user_agent} />
        )}
      </div>
      <div className="space-y-3">
        {event.details && (
          <div>
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
              Details
            </span>
            <pre className="mt-1 text-sm font-mono text-gray-400 bg-[#0a0a0f] rounded-lg p-3 overflow-auto max-h-48">
              {JSON.stringify(event.details, null, 2)}
            </pre>
          </div>
        )}
        {event.raw_payload && (
          <div>
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
              Raw Payload
            </span>
            <pre className="mt-1 text-sm font-mono text-gray-400 bg-[#0a0a0f] rounded-lg p-3 overflow-auto max-h-32">
              {event.raw_payload}
            </pre>
          </div>
        )}
        {event.geolocation && (
          <div>
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
              Geolocation
            </span>
            <div className="mt-1 text-sm text-gray-400 bg-[#0a0a0f] rounded-lg p-3 space-y-1">
              <GeoDisplay geo={event.geolocation} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function countryFlag(code?: string): string {
  if (!code || code.length !== 2) return '';
  const offset = 0x1F1E6 - 65;
  return String.fromCodePoint(
    code.codePointAt(0)! + offset,
    code.codePointAt(1)! + offset,
  );
}

function GeoDisplay({ geo }: { geo: Record<string, unknown> }) {
  const country = geo.country as string | undefined;
  const countryCode = geo.country_code as string | undefined;
  const city = geo.city as string | undefined;
  const isp = geo.isp as string | undefined;
  const org = geo.org as string | undefined;
  const lat = geo.lat as number | undefined;
  const lon = geo.lon as number | undefined;

  return (
    <>
      {country && (
        <p className="text-gray-300">
          {countryFlag(countryCode)} {country}
          {city ? `, ${city}` : ''}
        </p>
      )}
      {(isp || org) && (
        <p className="text-gray-500 text-xs">
          {[isp, org].filter(Boolean).join(' / ')}
        </p>
      )}
      {lat != null && lon != null && (
        <p className="text-gray-600 text-xs font-mono">
          {lat.toFixed(4)}, {lon.toFixed(4)}
        </p>
      )}
    </>
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
