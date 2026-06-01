'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ArrowLeft,
  ShieldBan,
} from 'lucide-react';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import SeverityBadge from '@/components/ui/SeverityBadge';
import { formatDate, formatRelativeTime, formatNumber } from '@/utils/formatters';
import { getAttacker, getAttackerEvents } from '@/lib/api';
import type { Event, Attacker } from '@/lib/api';
import clsx from 'clsx';

function countryFlag(code?: string | null): string {
  if (!code || code.length !== 2) return '';
  const offset = 0x1F1E6 - 65;
  return String.fromCodePoint(
    code.codePointAt(0)! + offset,
    code.codePointAt(1)! + offset,
  );
}

function formatThrottleExpiry(seconds: number): string {
  if (seconds >= 3600) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return m > 0 ? `${h}h ${m}m` : `${h}h`;
  }
  if (seconds >= 60) {
    return `${Math.floor(seconds / 60)}m`;
  }
  return `${seconds}s`;
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

export default function AttackerDetailPage({
  params,
}: {
  params: { ip: string };
}) {
  const ip = decodeURIComponent(params.ip);
  const [attacker, setAttacker] = useState<Attacker | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [events, setEvents] = useState<Event[]>([]);
  const [eventsLoading, setEventsLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setError(null);
    getAttacker(ip)
      .then((data) => setAttacker(data))
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load attacker'))
      .finally(() => setLoading(false));
  }, [ip]);

  useEffect(() => {
    setEventsLoading(true);
    getAttackerEvents(ip, { per_page: 10 })
      .then((data) => setEvents(data.items || []))
      .catch(() => {})
      .finally(() => setEventsLoading(false));
  }, [ip]);

  if (loading) {
    return (
      <div className="card p-12 text-center">
        <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
        <p className="mt-3 text-sm text-gray-500">Loading attacker...</p>
      </div>
    );
  }

  if (error || !attacker) {
    return (
      <div className="space-y-6">
        <Link
          href="/attackers"
          className="btn-secondary inline-flex items-center gap-2 text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to attackers
        </Link>
        <div className="card p-12 text-center">
          <p className="text-sm text-red-400">{error || 'Attacker not found'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          href="/attackers"
          className="btn-secondary flex items-center gap-2 text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to attackers
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-100">
            Attacker Detail
          </h1>
          <p className="text-sm text-gray-500 font-mono mt-1 flex items-center gap-2">
            {attacker.ip}
            {attacker.throttled && attacker.throttled.length > 0 && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-red-500/15 text-red-400 border border-red-500/30">
                <ShieldBan className="w-3 h-3" />
                Blocked
              </span>
            )}
          </p>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider">
            Total Events
          </span>
          <p className="text-lg font-mono text-amber-400 mt-1">
            {formatNumber(attacker.event_count)}
          </p>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider">
            Protocols
          </span>
          <div className="flex flex-wrap gap-1 mt-2">
            {attacker.protocols.map((p) => (
              <ProtocolBadge key={p} protocol={p} />
            ))}
          </div>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider">
            First Seen
          </span>
          <p className="text-sm text-gray-300 mt-1">
            {formatDate(attacker.first_seen, 'MMM d, yyyy')}
          </p>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider">
            Last Seen
          </span>
          <p className="text-sm text-gray-300 mt-1">
            {formatRelativeTime(attacker.last_seen)}
          </p>
        </div>
      </div>

      {/* Detail grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Geo details */}
        <div className="space-y-3">
          <h3 className="text-sm font-medium text-gray-300 mb-2">Geo Details</h3>
          <div className="card p-4 space-y-2">
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
            {attacker.throttled && attacker.throttled.length > 0 && (
              <div>
                <span className="text-xs font-medium text-red-400 uppercase tracking-wider flex items-center gap-1">
                  <ShieldBan className="w-3 h-3" />
                  Throttled
                </span>
                <div className="mt-1 space-y-1">
                  {attacker.throttled.map((t) => (
                    <div key={t.protocol} className="flex items-center gap-2 text-sm">
                      <ProtocolBadge protocol={t.protocol} />
                      <span className="text-gray-500">
                        blocked for {formatThrottleExpiry(t.expires_in)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Recent events */}
        <div className="space-y-3">
          <h3 className="text-sm font-medium text-gray-300 mb-2">Recent Events</h3>
          <div className="card overflow-hidden">
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
    </div>
  );
}
