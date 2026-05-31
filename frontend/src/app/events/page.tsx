'use client';

import React, { useEffect, useState, useCallback, useRef } from 'react';
import Link from 'next/link';
import {
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
import { useUrlFilters } from '@/utils/useUrlFilters';
import { getEvent, getBaseUrl } from '@/lib/api';
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

  const { searchParams, getParam, setParam, clearParams } = useUrlFilters();
  const linkedEventId = searchParams.get('event');
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);
  const [showFilters, setShowFilters] = useState(true);
  const panelRef = useRef<HTMLDivElement>(null);

  const filterEventType = getParam('event_type');
  const filterProtocol = getParam('protocol');
  const filterSeverity = getParam('severity');
  const filterStartDate = getParam('start_date');
  const filterEndDate = getParam('end_date');

  const loadEvents = useCallback(
    (page: number = 1) => {
      fetchEvents({
        page,
        per_page: 25,
        event_type: filterEventType || undefined,
        protocol: filterProtocol || undefined,
        severity: filterSeverity || undefined,
        start_date: filterStartDate || undefined,
        end_date: filterEndDate || undefined,
      });
    },
    [fetchEvents, filterEventType, filterProtocol, filterSeverity, filterStartDate, filterEndDate]
  );

  useEffect(() => {
    loadEvents(1);
  }, [loadEvents]);

  // Fetch and open the linked event from ?event=id
  useEffect(() => {
    if (!linkedEventId) return;
    getEvent(linkedEventId)
      .then((e) => {
        setSelectedEvent(e);
        setPanelOpen(true);
      })
      .catch(() => {});
  }, [linkedEventId]);

  // Close panel on Escape
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closePanel();
    };
    if (panelOpen) {
      document.addEventListener('keydown', handleKey);
      return () => document.removeEventListener('keydown', handleKey);
    }
  }, [panelOpen]);

  const openPanel = (event: Event) => {
    setSelectedEvent(event);
    setPanelOpen(true);
  };

  const closePanel = () => {
    setPanelOpen(false);
    // Clear the ?event= param if present
    if (linkedEventId) {
      setParam('event', '');
    }
  };

  const handleFilterChange = (key: string, value: string) => {
    setParam(key, value);
  };

  const clearFilters = () => {
    clearParams('event');
  };

  const hasActiveFilters = filterEventType || filterProtocol || filterSeverity || filterStartDate || filterEndDate;

  const handleExport = () => {
    const params = new URLSearchParams();
    if (filterEventType) params.set('event_type', filterEventType);
    if (filterProtocol) params.set('protocol', filterProtocol);
    if (filterSeverity) params.set('severity', filterSeverity);
    if (filterStartDate) params.set('start_date', filterStartDate);
    if (filterEndDate) params.set('end_date', filterEndDate);
    const qs = params.toString();
    window.open(`${getBaseUrl()}/api/events/export${qs ? `?${qs}` : ''}`, '_blank');
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
                value={filterEventType}
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
              <label className="label-text">Severity</label>
              <select
                value={filterSeverity}
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
                value={filterStartDate}
                onChange={(e) => handleFilterChange('start_date', e.target.value)}
                className="input-field w-full"
              />
            </div>
            <div>
              <label className="label-text">End Date</label>
              <input
                type="date"
                value={filterEndDate}
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

      {/* Table */}
      <div className="card overflow-hidden relative">
        {eventsLoading && events.length > 0 && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-[#0e0e14]/60 backdrop-blur-sm">
            <div className="flex flex-col items-center gap-3 text-gray-400 text-sm">
              <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
              Loading events...
            </div>
          </div>
        )}
        {eventsLoading && events.length === 0 ? (
          <div className="p-12 text-center">
            <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
            <p className="mt-3 text-sm text-gray-500">Loading events...</p>
          </div>
        ) : events.length === 0 ? (
          <div className="p-12 text-center">
            <p className="text-sm text-gray-500">No events match your filters</p>
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
                {events.map((event) => (
                    <tr
                      key={event.id}
                      className={clsx(
                        'cursor-pointer hover:bg-[#1c1c28] transition-colors',
                        panelOpen && selectedEvent?.id === event.id && 'bg-[#1c1c28]'
                      )}
                      onClick={() => openPanel(event)}
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
                ))}
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

      {/* Slide-over panel */}
      {panelOpen && selectedEvent && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/40 z-40 transition-opacity"
            onClick={closePanel}
          />

          {/* Panel */}
          <div
            ref={panelRef}
            className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-[#12121a] border-l border-[#2a2a3a] shadow-2xl overflow-y-auto animate-slide-in-right"
          >
            {/* Panel header */}
            <div className="sticky top-0 bg-[#12121a] border-b border-[#2a2a3a] px-6 py-4 flex items-center justify-between z-10">
              <div>
                <h2 className="text-lg font-semibold text-gray-100">Event Detail</h2>
                <p className="text-xs text-gray-500 font-mono mt-0.5">
                  {selectedEvent.id}
                </p>
              </div>
              <button
                onClick={closePanel}
                className="p-1.5 rounded-lg hover:bg-[#2a2a3a] text-gray-400 hover:text-gray-200 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Panel body */}
            <div className="px-6 py-5 space-y-6">
              {/* Summary badges */}
              <div className="flex flex-wrap items-center gap-2">
                <ProtocolBadge protocol={selectedEvent.protocol} />
                <SeverityBadge severity={selectedEvent.severity} />
                <span className="text-xs text-gray-500">
                  {formatRelativeTime(selectedEvent.timestamp)}
                </span>
              </div>

              {/* Fields */}
              <div className="space-y-3">
                <DetailRow label="Event Type" value={selectedEvent.event_type.replace(/_/g, ' ')} />
                <DetailRow label="Source IP" value={selectedEvent.source_ip} mono link={`/attackers/${selectedEvent.source_ip}`} />
                <DetailRow label="Source Port" value={selectedEvent.source_port?.toString() || 'N/A'} mono />
                <DetailRow label="Destination Port" value={selectedEvent.destination_port?.toString() || 'N/A'} mono />
                <DetailRow label="Timestamp" value={formatDate(selectedEvent.timestamp)} />
                {selectedEvent.session_id && (
                  <DetailRow label="Session" value={selectedEvent.session_id} mono link={`/sessions/${selectedEvent.session_id}`} />
                )}
                {selectedEvent.user_agent && (
                  <DetailRow label="User Agent" value={selectedEvent.user_agent} />
                )}
              </div>

              {/* Details JSON */}
              {selectedEvent.details && (
                <div>
                  <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Details
                  </span>
                  <pre className="mt-1 text-sm font-mono text-gray-400 bg-[#0a0a0f] rounded-lg p-3 overflow-auto max-h-48">
                    {JSON.stringify(selectedEvent.details, null, 2)}
                  </pre>
                </div>
              )}

              {/* Raw payload */}
              {selectedEvent.raw_payload && (
                <div>
                  <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Raw Payload
                  </span>
                  <pre className="mt-1 text-sm font-mono text-gray-400 bg-[#0a0a0f] rounded-lg p-3 overflow-auto max-h-32">
                    {selectedEvent.raw_payload}
                  </pre>
                </div>
              )}

              {/* Geolocation */}
              {selectedEvent.geolocation && (
                <div>
                  <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Geolocation
                  </span>
                  <div className="mt-1 text-sm text-gray-400 bg-[#0a0a0f] rounded-lg p-3 space-y-1">
                    <GeoDisplay geo={selectedEvent.geolocation} />
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

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
  link,
}: {
  label: string;
  value: string;
  mono?: boolean;
  link?: string;
}) {
  return (
    <div>
      <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
        {label}
      </span>
      {link ? (
        <Link href={link} className={clsx('text-sm text-amber-400 hover:text-amber-300 mt-0.5 block transition-colors', mono && 'font-mono')}>
          {value}
        </Link>
      ) : (
        <p className={clsx('text-sm text-gray-300 mt-0.5', mono && 'font-mono')}>
          {value}
        </p>
      )}
    </div>
  );
}
