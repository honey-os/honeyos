'use client';

import React from 'react';
import clsx from 'clsx';
import { Activity } from 'lucide-react';
import SeverityBadge from '@/components/ui/SeverityBadge';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import { formatRelativeTime } from '@/utils/formatters';
import type { Event } from '@/lib/api';

interface EventFeedProps {
  events: Event[];
  maxItems?: number;
  className?: string;
  onEventClick?: (event: Event) => void;
}

export default function EventFeed({
  events,
  maxItems = 10,
  className,
  onEventClick,
}: EventFeedProps) {
  const displayEvents = events.slice(0, maxItems);

  return (
    <div className={clsx('card', className)}>
      <div className="px-5 py-4 border-b border-[#2a2a3a] flex items-center gap-2">
        <Activity className="w-4 h-4 text-amber-500" />
        <h3 className="text-sm font-semibold text-gray-200">Recent Events</h3>
        <span className="ml-auto text-xs text-gray-500 font-mono">
          {events.length} total
        </span>
      </div>

      <div className="divide-y divide-[#2a2a3a]/50">
        {displayEvents.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-600">
            No events recorded yet
          </div>
        ) : (
          displayEvents.map((event) => (
            <div
              key={event.id}
              className={clsx(
                'px-5 py-3 flex items-center gap-4 transition-colors',
                onEventClick
                  ? 'cursor-pointer hover:bg-[#1c1c28]'
                  : 'hover:bg-[#16161f]/50'
              )}
              onClick={() => onEventClick?.(event)}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-medium text-gray-200 truncate">
                    {event.event_type}
                  </span>
                  <ProtocolBadge protocol={event.protocol} />
                </div>
                <div className="flex items-center gap-3 text-xs text-gray-500">
                  <span className="font-mono">{event.source_ip}</span>
                  {event.destination_port && (
                    <span className="font-mono">:{event.destination_port}</span>
                  )}
                  <span>{formatRelativeTime(event.timestamp)}</span>
                </div>
              </div>

              <SeverityBadge severity={event.severity} />
            </div>
          ))
        )}
      </div>
    </div>
  );
}
