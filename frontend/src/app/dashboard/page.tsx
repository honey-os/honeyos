'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Zap,
  Activity,
  Radio,
  Server,
  AlertTriangle,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  LabelList,
} from 'recharts';
import MetricsCard from '@/components/ui/MetricsCard';
import SeverityBadge from '@/components/ui/SeverityBadge';
import ProtocolBadge from '@/components/ui/ProtocolBadge';
import EventFeed from '@/components/shared/EventFeed';
import { useStore } from '@/stores/useStore';
import { formatDate, formatNumber, formatRelativeTime } from '@/utils/formatters';

/** Locked protocol → hex color map matching ProtocolBadge palette. */
const PROTOCOL_COLORS: Record<string, string> = {
  ssh: '#10b981',    // emerald
  http: '#3b82f6',   // blue
  https: '#3b82f6',  // blue
  telnet: '#8b5cf6', // purple
  ftp: '#06b6d4',    // cyan
  mysql: '#f97316',  // orange
  postgresql: '#0ea5e9',  // sky
  smb: '#f43f5e',    // rose
  rdp: '#6366f1',    // indigo
  dns: '#14b8a6',    // teal
  smtp: '#ec4899',   // pink
};

const DEFAULT_PROTOCOL_COLOR = '#6b7280'; // gray

function protocolColor(protocol: string): string {
  return PROTOCOL_COLORS[protocol.toLowerCase()] || DEFAULT_PROTOCOL_COLOR;
}

function countryFlag(code?: string): string {
  if (!code || code.length !== 2) return '';
  const offset = 0x1F1E6 - 65; // 'A' = 65
  return String.fromCodePoint(
    code.codePointAt(0)! + offset,
    code.codePointAt(1)! + offset,
  );
}

const threatLevelColors: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
  none: 'text-gray-400',
};

export default function DashboardPage() {
  const {
    dashboardSummary,
    dashboardTimeline,
    dashboardLoading,
    dashboardError,
    fetchDashboard,
  } = useStore();

  const [timelineHours, setTimelineHours] = useState(24);

  useEffect(() => {
    fetchDashboard(timelineHours);

    const interval = setInterval(() => {
      fetchDashboard(timelineHours);
    }, 30000);

    return () => clearInterval(interval);
  }, [fetchDashboard, timelineHours]);

  const summary = dashboardSummary;
  const initialLoading = dashboardLoading && !summary;

  if (initialLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">
            Real-time overview of honeypot activity and threats
          </p>
        </div>
        <div className="flex flex-col items-center justify-center py-32 text-gray-500 text-sm gap-3">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          Loading dashboard...
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">
            Real-time overview of honeypot activity and threats
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <span className="text-gray-500">Timeline:</span>
          {[6, 12, 24, 48].map((h) => (
            <button
              key={h}
              onClick={() => setTimelineHours(h)}
              className={
                timelineHours === h
                  ? 'px-3 py-1 rounded-md bg-amber-500/20 text-amber-400 border border-amber-500/30 font-medium'
                  : 'px-3 py-1 rounded-md text-gray-500 hover:text-gray-300 transition-colors'
              }
            >
              {h}h
            </button>
          ))}
        </div>
      </div>

      {dashboardError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {dashboardError}
        </div>
      )}

      {/* Metrics cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricsCard
          icon={Zap}
          label="Conn/sec"
          value={summary?.connections_per_second?.toFixed(1) ?? '0'}
          iconColor="text-purple-500"
        />
        <MetricsCard
          icon={Activity}
          label="Total Events"
          value={formatNumber(summary?.total_events)}
          iconColor="text-amber-500"
        />
        <Link href="/sessions?status=active">
          <MetricsCard
            icon={Radio}
            label="Active Sessions"
            value={formatNumber(summary?.active_sessions)}
            iconColor="text-blue-500"
            className="cursor-pointer hover:border-amber-500/30"
          />
        </Link>
        <Link href="/honeypots">
          <MetricsCard
            icon={Server}
            label="Active Honeypots"
            value={formatNumber(summary?.active_honeypots)}
            iconColor="text-green-500"
            className="cursor-pointer hover:border-amber-500/30"
          />
        </Link>
        <Link href="/threat-level">
          <MetricsCard
            icon={AlertTriangle}
            label="Threat Level"
            value={
              <span
                className={
                  threatLevelColors[String(summary?.threat_level?.level || 'none')] ||
                  'text-gray-400'
                }
              >
                {String(summary?.threat_level?.level || 'none').toUpperCase()}
              </span>
            }
            iconColor="text-red-500"
            className="cursor-pointer hover:border-amber-500/30"
          />
        </Link>
      </div>

      {/* Timeline chart & Protocol breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Timeline */}
        <div className="lg:col-span-3 card p-5">
          <h3 className="text-sm font-semibold text-gray-200 mb-4">
            Event Timeline (last {timelineHours}h)
          </h3>
          {dashboardLoading && dashboardTimeline.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-gray-600 text-sm">
              Loading timeline...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={dashboardTimeline}>
                <defs>
                  <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#2a2a3a"
                  vertical={false}
                />
                <XAxis
                  dataKey="timestamp"
                  tick={{ fill: '#64748b', fontSize: 11 }}
                  tickLine={false}
                  axisLine={{ stroke: '#2a2a3a' }}
                  tickFormatter={(val: string) => formatDate(val, 'HH:mm')}
                  interval={Math.max(0, Math.floor((timelineHours * 6) / 12) - 1)}
                />
                <YAxis
                  tick={{ fill: '#64748b', fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  width={40}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#16161f',
                    border: '1px solid #2a2a3a',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                    fontSize: '12px',
                  }}
                  labelStyle={{ color: '#e2e8f0' }}
                  itemStyle={{ color: '#e2e8f0' }}
                  labelFormatter={(val: string) => formatDate(val, 'MMM d, HH:mm')}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#f59e0b"
                  strokeWidth={2}
                  fill="url(#eventGradient)"
                  name="Events"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Protocol breakdown */}
        <div className="lg:col-span-2 card p-5">
          <h3 className="text-sm font-semibold text-gray-200 mb-4">
            Protocol Breakdown
          </h3>
          {summary?.protocol_breakdown && summary.protocol_breakdown.length > 0 ? (
            <ResponsiveContainer width="100%" height={summary.protocol_breakdown.length * 32 + 24}>
              <BarChart
                data={summary.protocol_breakdown}
                layout="vertical"
                margin={{ top: 0, right: 60, bottom: 0, left: 0 }}
                barCategoryGap="20%"
              >
                <XAxis
                  type="number"
                  scale="log"
                  domain={[1, 'auto']}
                  allowDataOverflow
                  tick={{ fill: '#6b7280', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v: number) => formatNumber(v)}
                />
                <YAxis
                  type="category"
                  dataKey="protocol"
                  width={84}
                  tick={{ fill: '#d1d5db', fontSize: 11, fontFamily: 'monospace' }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v: string) => v.toUpperCase()}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                  contentStyle={{
                    backgroundColor: '#16161f',
                    border: '1px solid #2a2a3a',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                    fontSize: '12px',
                  }}
                  labelStyle={{ color: '#e2e8f0' }}
                  itemStyle={{ color: '#e2e8f0' }}
                  formatter={(value: number) => [formatNumber(value), 'Events']}
                  labelFormatter={(label: string) => label.toUpperCase()}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {summary.protocol_breakdown.map((entry, idx) => (
                    <Cell key={idx} fill={protocolColor(entry.protocol)} />
                  ))}
                  <LabelList
                    dataKey="count"
                    position="right"
                    formatter={(v: number) => formatNumber(v)}
                    style={{ fill: '#d1d5db', fontSize: 11, fontFamily: 'monospace' }}
                  />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-600 text-sm">
              No protocol data
            </div>
          )}
        </div>
      </div>

      {/* Top attackers & Recent events */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top attackers */}
        <div className="card">
          <div className="px-5 py-4 border-b border-[#2a2a3a]">
            <h3 className="text-sm font-semibold text-gray-200">
              Top Attackers
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2a2a3a]">
                  <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    IP Address
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Location
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Events
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Last Seen
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#2a2a3a]/50">
                {summary?.top_attackers && summary.top_attackers.length > 0 ? (
                  summary.top_attackers.map((attacker) => (
                    <tr
                      key={attacker.ip}
                      className="hover:bg-[#1c1c28] transition-colors"
                    >
                      <td className="px-5 py-3 font-mono text-sm whitespace-nowrap">
                        <Link
                          href={`/attackers/${encodeURIComponent(attacker.ip)}`}
                          className="text-amber-400 hover:text-amber-300"
                        >
                          {attacker.ip}
                        </Link>
                      </td>
                      <td className="px-5 py-3 text-sm text-gray-300 whitespace-nowrap">
                        {attacker.country_code ? (
                          <span title={[attacker.country, attacker.org].filter(Boolean).join(' — ')}>
                            {countryFlag(attacker.country_code)} {attacker.country_code}
                          </span>
                        ) : (
                          <span className="text-gray-600">--</span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-sm text-gray-300 whitespace-nowrap">
                        {formatNumber(attacker.count)}
                      </td>
                      <td className="px-5 py-3 text-sm text-gray-500 whitespace-nowrap">
                        {formatRelativeTime(attacker.last_seen)}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td
                      colSpan={4}
                      className="px-5 py-8 text-center text-sm text-gray-600"
                    >
                      No attacker data available
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent events */}
        <EventFeed events={summary?.recent_events || []} maxItems={10} />
      </div>
    </div>
  );
}
