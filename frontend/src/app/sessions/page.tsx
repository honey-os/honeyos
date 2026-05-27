'use client';

import React, { useEffect, useCallback } from 'react';
import {
  Terminal,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import { useStore } from '@/stores/useStore';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import { formatDuration, formatRelativeTime } from '@/utils/formatters';
import { useUrlFilters } from '@/utils/useUrlFilters';
import clsx from 'clsx';

const statusConfig: Record<string, { bg: string; text: string; dot: string }> = {
  active: {
    bg: 'bg-green-500/15 border-green-500/30',
    text: 'text-green-400',
    dot: 'bg-green-500',
  },
  completed: {
    bg: 'bg-gray-500/15 border-gray-500/30',
    text: 'text-gray-400',
    dot: 'bg-gray-500',
  },
  terminated: {
    bg: 'bg-red-500/15 border-red-500/30',
    text: 'text-red-400',
    dot: 'bg-red-500',
  },
};

export default function SessionsPage() {
  const {
    sessions,
    sessionsTotal,
    sessionsPage,
    sessionsPages,
    sessionsLoading,
    sessionsError,
    fetchSessions,
  } = useStore();

  const router = useRouter();
  const { getParam, setParam } = useUrlFilters();

  const filterProtocol = getParam('protocol');
  const filterStatus = getParam('status');

  const loadSessions = useCallback(
    (page: number = 1) => {
      fetchSessions({
        page,
        per_page: 20,
        protocol: filterProtocol || undefined,
        status: filterStatus || undefined,
      });
    },
    [fetchSessions, filterProtocol, filterStatus]
  );

  useEffect(() => {
    loadSessions(1);
  }, [loadSessions]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Sessions</h1>
        <p className="text-sm text-gray-500 mt-1">
          {sessionsTotal} total sessions recorded
        </p>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <select
          value={filterProtocol}
          onChange={(e) => setParam('protocol', e.target.value)}
          className="select-field text-sm"
        >
          <option value="">All protocols</option>
          {['ssh', 'http', 'https', 'telnet', 'ftp', 'mysql', 'postgresql', 'dns', 'smb'].map((p) => (
            <option key={p} value={p}>
              {p.toUpperCase()}
            </option>
          ))}
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setParam('status', e.target.value)}
          className="select-field text-sm"
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="completed">Completed</option>
          <option value="terminated">Terminated</option>
        </select>
      </div>

      {/* Error */}
      {sessionsError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {sessionsError}
        </div>
      )}

      {/* Session cards */}
      {sessionsLoading && sessions.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="mt-3 text-sm text-gray-500">Loading sessions...</p>
        </div>
      ) : sessions.length === 0 ? (
        <div className="card p-12 text-center text-sm text-gray-600">
          No sessions found
        </div>
      ) : (
        <div className="space-y-3">
          {sessions.map((session) => {
            const sc =
              statusConfig[session.status] || statusConfig.completed;

            return (
              <div
                key={session.id}
                className="card-hover p-4 cursor-pointer"
                onClick={() => router.push(`/sessions/${session.id}`)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-lg bg-[#0a0a0f] flex items-center justify-center">
                      <Terminal className="w-5 h-5 text-amber-500" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-amber-400">
                          {session.source_ip}
                        </span>
                        <ProtocolBadge protocol={session.protocol} />
                        <span
                          className={clsx(
                            'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border',
                            sc.bg,
                            sc.text
                          )}
                        >
                          <span
                            className={clsx(
                              'w-1.5 h-1.5 rounded-full',
                              sc.dot,
                              session.status === 'active' && 'animate-pulse'
                            )}
                          />
                          {session.status}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                        <span>
                          Started{' '}
                          {formatRelativeTime(session.start_time)}
                        </span>
                        <span>
                          Duration: {formatDuration(session.duration_seconds)}
                        </span>
                        <span>{session.commands_count} commands</span>
                      </div>
                    </div>
                  </div>
                  <ChevronRight className="w-5 h-5 text-gray-600" />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {sessionsPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-500">
            Page {sessionsPage} of {sessionsPages}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => loadSessions(sessionsPage - 1)}
              disabled={sessionsPage <= 1}
              className="btn-secondary flex items-center gap-1 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
              Previous
            </button>
            <button
              onClick={() => loadSessions(sessionsPage + 1)}
              disabled={sessionsPage >= sessionsPages}
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
