'use client';

import React, { useEffect, useState } from 'react';
import {
  Terminal,
  ArrowLeft,
  Clock,
  Hash,
  Shield,
  KeyRound,
} from 'lucide-react';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import SessionPlayer from '@/components/shared/SessionPlayer';
import { formatDate, formatDuration } from '@/utils/formatters';
import { getSession, getFeatures, identifyMalware } from '@/lib/api';
import type { Session } from '@/lib/api';
import clsx from 'clsx';
import Link from 'next/link';

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

export default function SessionDetailPage({
  params,
}: {
  params: { id: string };
}) {
  const { id } = params;
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [threatfoxAvailable, setThreatfoxAvailable] = useState<boolean | null>(null);
  const [threatChecking, setThreatChecking] = useState(false);
  const [threatError, setThreatError] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(null);
    getSession(id)
      .then((data) => setSession(data))
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load session'))
      .finally(() => setLoading(false));
  }, [id]);

  useEffect(() => {
    getFeatures()
      .then((f) => setThreatfoxAvailable(f.threatfox))
      .catch(() => setThreatfoxAvailable(false));
  }, []);

  // Auto-trigger threat intel check when key is available and no cached results
  useEffect(() => {
    if (!session || session.threat_intel || !threatfoxAvailable || threatChecking) return;
    let cancelled = false;
    setThreatChecking(true);
    setThreatError(false);
    identifyMalware(session.id)
      .then((result) => {
        if (!cancelled) setSession((s) => s ? { ...s, threat_intel: result } : s);
      })
      .catch(() => {
        if (!cancelled) setThreatError(true);
      })
      .finally(() => {
        if (!cancelled) setThreatChecking(false);
      });
    return () => { cancelled = true; };
  }, [session?.id, session?.threat_intel, threatfoxAvailable]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) {
    return (
      <div className="card p-12 text-center">
        <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
        <p className="mt-3 text-sm text-gray-500">Loading session...</p>
      </div>
    );
  }

  if (error || !session) {
    return (
      <div className="space-y-6">
        <Link
          href="/sessions"
          className="btn-secondary inline-flex items-center gap-2 text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to sessions
        </Link>
        <div className="card p-12 text-center">
          <p className="text-sm text-red-400">{error || 'Session not found'}</p>
        </div>
      </div>
    );
  }

  const sc = statusConfig[session.status] || statusConfig.completed;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            href="/sessions"
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to sessions
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-100">
              Session Detail
            </h1>
            <p className="text-sm text-gray-500 font-mono mt-1">
              {session.id}
            </p>
          </div>
        </div>
      </div>

      {/* Session info cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider">
            Source IP
          </span>
          <p className="text-lg font-mono text-amber-400 mt-1">
            {session.source_ip}
          </p>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider">
            Protocol
          </span>
          <div className="mt-2">
            <ProtocolBadge protocol={session.protocol} />
          </div>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider">
            Duration
          </span>
          <p className="text-lg text-gray-200 mt-1 flex items-center gap-2">
            <Clock className="w-4 h-4 text-gray-500" />
            {formatDuration(session.duration_seconds)}
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
              {session.status.charAt(0).toUpperCase() +
                session.status.slice(1)}
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
            {formatDate(session.start_time)}
          </p>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider">
            End Time
          </span>
          <p className="text-gray-300 mt-1">
            {session.end_time
              ? formatDate(session.end_time)
              : 'Still active'}
          </p>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider flex items-center gap-1">
            <Hash className="w-3 h-3" />
            Commands Count
          </span>
          <p className="text-gray-300 mt-1 font-mono">
            {session.commands_count}
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
          commands={session.commands}
          keystrokes={session.keystrokes}
        />
      </div>

      {/* File transfers */}
      {session.file_transfers &&
        session.file_transfers.length > 0 && (
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
                  {session.file_transfers.map((ft, idx) => (
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

      {/* Threat Intelligence — always visible */}
      <div className="card">
        <div className="px-5 py-4 border-b border-[#2a2a3a]">
          <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <Shield className="w-4 h-4 text-amber-500" />
            Threat Intelligence
          </h3>
        </div>
        {threatfoxAvailable === false ? (
          <div className="px-5 py-8 text-center">
            <KeyRound className="w-5 h-5 text-gray-600 mx-auto mb-2" />
            <p className="text-sm text-gray-500">
              Add your{' '}
              <a
                href="https://auth.abuse.ch"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-500 hover:underline"
              >
                abuse.ch
              </a>{' '}
              auth key to enable threat intelligence
            </p>
            <p className="text-xs text-gray-600 mt-1">
              Set <code className="text-gray-400">ABUSECH_API_KEY</code> in your environment
            </p>
          </div>
        ) : threatChecking || threatfoxAvailable === null ? (
          <div className="px-5 py-8 text-center">
            <div className="inline-block w-5 h-5 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
            <p className="mt-2 text-sm text-gray-500">
              Checking URLhaus &amp; ThreatFox...
            </p>
          </div>
        ) : threatError ? (
          <div className="px-5 py-8 text-center text-sm text-gray-500">
            Failed to check threat intelligence
          </div>
        ) : session.threat_intel ? (
          <>
            {session.threat_intel.matches.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-[#2a2a3a]">
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        IOC
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Source
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Malware
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Threat Type
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Confidence
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        First Seen
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        Tags
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#2a2a3a]/50">
                    {session.threat_intel.matches.map((m, idx) => (
                      <tr key={idx} className="hover:bg-[#1c1c28]">
                        <td className="px-5 py-3 text-sm font-mono text-amber-400">
                          {m.reference ? (
                            <a
                              href={m.reference}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="hover:underline"
                            >
                              {m.ioc}
                            </a>
                          ) : (
                            m.ioc
                          )}
                        </td>
                        <td className="px-5 py-3 text-sm">
                          <span
                            className={clsx(
                              'inline-flex px-2 py-0.5 rounded-full text-xs font-medium',
                              m.source === 'urlhaus'
                                ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                                : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            )}
                          >
                            {m.source === 'urlhaus' ? 'URLhaus' : 'ThreatFox'}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-sm text-red-400 font-medium">
                          {m.malware}
                        </td>
                        <td className="px-5 py-3 text-sm text-gray-400">
                          {m.threat_type}
                        </td>
                        <td className="px-5 py-3 text-sm text-gray-300">
                          {m.confidence_level > 0 ? `${m.confidence_level}%` : '\u2014'}
                        </td>
                        <td className="px-5 py-3 text-sm text-gray-400">
                          {m.first_seen}
                        </td>
                        <td className="px-5 py-3 text-sm">
                          <div className="flex flex-wrap gap-1">
                            {m.tags.map((tag, ti) => (
                              <span
                                key={ti}
                                className="px-1.5 py-0.5 text-xs rounded bg-gray-700/50 text-gray-400"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="px-5 py-8 text-center text-sm text-gray-500">
                No known threats found for{' '}
                {session.threat_intel.iocs_searched.length} IOC
                {session.threat_intel.iocs_searched.length !== 1
                  ? 's'
                  : ''}{' '}
                searched
              </div>
            )}
            <div className="px-5 py-3 border-t border-[#2a2a3a] text-xs text-gray-600">
              Analyzed {formatDate(session.threat_intel.analyzed_at)} via
              abuse.ch (ThreatFox + URLhaus)
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
}
