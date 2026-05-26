'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  Terminal,
  ChevronLeft,
  ChevronRight,
  ArrowLeft,
  Clock,
  Hash,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import SessionPlayer from '@/components/shared/SessionPlayer';
import { formatDate, formatDuration, formatRelativeTime } from '@/utils/formatters';
import { getSession } from '@/lib/api';
import type { Session } from '@/lib/api';
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
    selectedSession,
    setSelectedSession,
  } = useStore();

  const [detailLoading, setDetailLoading] = useState(false);
  const [filterProtocol, setFilterProtocol] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

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

  const handleViewSession = async (session: Session) => {
    setDetailLoading(true);
    try {
      const detail = await getSession(session.id);
      setSelectedSession(detail);
    } catch {
      setSelectedSession(session);
    } finally {
      setDetailLoading(false);
    }
  };

  // ---- Session detail view ----
  if (selectedSession) {
    const sc = statusConfig[selectedSession.status] || statusConfig.completed;

    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <button
            onClick={() => setSelectedSession(null)}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to sessions
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-100">
              Session Detail
            </h1>
            <p className="text-sm text-gray-500 font-mono mt-1">
              {selectedSession.id}
            </p>
          </div>
        </div>

        {/* Session info cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="card p-4">
            <span className="text-xs text-gray-500 uppercase tracking-wider">
              Source IP
            </span>
            <p className="text-lg font-mono text-amber-400 mt-1">
              {selectedSession.source_ip}
            </p>
          </div>
          <div className="card p-4">
            <span className="text-xs text-gray-500 uppercase tracking-wider">
              Protocol
            </span>
            <div className="mt-2">
              <ProtocolBadge protocol={selectedSession.protocol} />
            </div>
          </div>
          <div className="card p-4">
            <span className="text-xs text-gray-500 uppercase tracking-wider">
              Duration
            </span>
            <p className="text-lg text-gray-200 mt-1 flex items-center gap-2">
              <Clock className="w-4 h-4 text-gray-500" />
              {formatDuration(selectedSession.duration_seconds)}
            </p>
          </div>
          <div className="card p-4">
            <span className="text-xs text-gray-500 uppercase tracking-wider">
              Status
            </span>
            <div className="mt-2">
              <span
                className={clsx(
                  'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border',
                  sc.bg,
                  sc.text
                )}
              >
                <span className={clsx('w-1.5 h-1.5 rounded-full', sc.dot)} />
                {selectedSession.status.charAt(0).toUpperCase() +
                  selectedSession.status.slice(1)}
              </span>
            </div>
          </div>
        </div>

        {/* Timeline */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-sm">
          <div className="card p-4">
            <span className="text-xs text-gray-500 uppercase tracking-wider">
              Start Time
            </span>
            <p className="text-gray-300 mt-1">
              {formatDate(selectedSession.start_time)}
            </p>
          </div>
          <div className="card p-4">
            <span className="text-xs text-gray-500 uppercase tracking-wider">
              End Time
            </span>
            <p className="text-gray-300 mt-1">
              {selectedSession.end_time
                ? formatDate(selectedSession.end_time)
                : 'Still active'}
            </p>
          </div>
          <div className="card p-4">
            <span className="text-xs text-gray-500 uppercase tracking-wider flex items-center gap-1">
              <Hash className="w-3 h-3" />
              Commands Count
            </span>
            <p className="text-gray-300 mt-1 font-mono">
              {selectedSession.commands_count}
            </p>
          </div>
        </div>

        {/* Session replay */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-gray-200 mb-4 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-amber-500" />
            Session Replay
          </h3>
          <SessionPlayer
            commands={selectedSession.commands}
            keystrokes={selectedSession.keystrokes}
          />
        </div>

        {/* File transfers */}
        {selectedSession.file_transfers &&
          selectedSession.file_transfers.length > 0 && (
            <div className="card">
              <div className="px-5 py-4 border-b border-[#2a2a3a]">
                <h3 className="text-sm font-semibold text-gray-200">
                  File Transfers
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-[#2a2a3a]">
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Filename
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Direction
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Size
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#2a2a3a]/50">
                    {selectedSession.file_transfers.map((ft, idx) => (
                      <tr key={idx} className="hover:bg-[#1c1c28]">
                        <td className="px-5 py-3 text-sm font-mono text-gray-300">
                          {ft.filename}
                        </td>
                        <td className="px-5 py-3 text-sm text-gray-400">
                          {ft.direction}
                        </td>
                        <td className="px-5 py-3 text-sm font-mono text-gray-400">
                          {ft.size} bytes
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
      </div>
    );
  }

  // ---- Session list view ----
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
          onChange={(e) => setFilterProtocol(e.target.value)}
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
          onChange={(e) => setFilterStatus(e.target.value)}
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
                onClick={() => handleViewSession(session)}
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

      {/* Detail loading overlay */}
      {detailLoading && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="card p-8">
            <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
            <p className="mt-3 text-sm text-gray-400">Loading session...</p>
          </div>
        </div>
      )}
    </div>
  );
}
