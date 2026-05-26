'use client';

import React, { useEffect } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  ArrowLeft,
  Users,
  Radio,
  Flame,
  Activity,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import { formatNumber } from '@/utils/formatters';
import clsx from 'clsx';
import type { ThreatLevel } from '@/lib/api';

const levelConfig: Record<
  string,
  { color: string; bg: string; border: string; description: string }
> = {
  critical: {
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    description:
      'Widespread, multi-vector attack in progress. Multiple unique attackers are probing across several protocols with high-severity events detected.',
  },
  high: {
    color: 'text-orange-400',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    description:
      'Significant attack activity detected. Multiple attackers or multi-protocol reconnaissance is underway with notable severity.',
  },
  medium: {
    color: 'text-yellow-400',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    description:
      'Moderate honeypot activity. Some scanning or brute-force attempts are occurring, but the attack surface is limited.',
  },
  low: {
    color: 'text-green-400',
    bg: 'bg-green-500/10',
    border: 'border-green-500/30',
    description:
      'Minimal or no recent activity. The network is quiet with little to no attacker engagement in the last hour.',
  },
  none: {
    color: 'text-gray-400',
    bg: 'bg-gray-500/10',
    border: 'border-gray-500/30',
    description: 'No data available to calculate threat level.',
  },
};

function scoreBarColor(score: number): string {
  if (score >= 80) return 'bg-red-500';
  if (score >= 50) return 'bg-orange-500';
  if (score >= 20) return 'bg-yellow-500';
  return 'bg-green-500';
}

interface FactorCardProps {
  icon: React.ElementType;
  label: string;
  value: number;
  formula: string;
  points: number;
  maxDescription: string;
}

function FactorCard({
  icon: Icon,
  label,
  value,
  formula,
  points,
  maxDescription,
}: FactorCardProps) {
  return (
    <div className="card p-4 space-y-3">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-amber-500/10 flex items-center justify-center">
          <Icon className="w-4 h-4 text-amber-500" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-gray-300">{label}</p>
          <p className="text-xs text-gray-500">{formula}</p>
        </div>
        <span className="text-lg font-bold font-mono text-gray-100">
          {formatNumber(value)}
        </span>
      </div>
      <div className="flex items-center justify-between text-xs">
        <span className="text-amber-400 font-mono font-medium">
          +{points} pts
        </span>
        <span className="text-gray-500">{maxDescription}</span>
      </div>
    </div>
  );
}

export default function ThreatLevelPage() {
  const { dashboardSummary, dashboardLoading, fetchDashboard } = useStore();

  useEffect(() => {
    fetchDashboard();
    const interval = setInterval(() => fetchDashboard(), 30000);
    return () => clearInterval(interval);
  }, [fetchDashboard]);

  const threat: ThreatLevel | null = dashboardSummary?.threat_level ?? null;
  const level = threat?.level || 'none';
  const config = levelConfig[level] || levelConfig.none;
  const score = threat?.score ?? 0;

  // Reconstruct individual score components from the raw values
  const volumePoints = threat
    ? Math.min(100, Math.round(Math.log2(threat.recent_events + 1) * 2))
    : 0;
  const breadthPoints = threat
    ? Math.round(Math.sqrt(threat.unique_attackers) * 4)
    : 0;
  const reconPoints = threat ? threat.unique_protocols * 3 : 0;
  const severityPoints = threat
    ? Math.round(Math.sqrt(threat.high_severity_events) * 3)
    : 0;

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Back link */}
      <Link
        href="/dashboard"
        className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Dashboard
      </Link>

      {/* Header card */}
      <div className={clsx('card p-6', config.border)}>
        <div className="flex items-start gap-4">
          <div
            className={clsx(
              'w-14 h-14 rounded-xl flex items-center justify-center shrink-0',
              config.bg
            )}
          >
            <AlertTriangle className={clsx('w-7 h-7', config.color)} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-1">
              <h1 className="text-2xl font-bold text-gray-100">Threat Level</h1>
              <span
                className={clsx(
                  'px-3 py-1 rounded-md text-sm font-bold uppercase tracking-wider border',
                  config.color,
                  config.bg,
                  config.border
                )}
              >
                {level}
              </span>
            </div>
            <p className="text-sm text-gray-400 mt-2">{config.description}</p>
          </div>
        </div>

        {/* Score bar */}
        <div className="mt-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
              Composite Score
            </span>
            <span className="text-sm font-bold font-mono text-gray-200">
              {score} / 100
            </span>
          </div>
          <div className="h-3 bg-[#1c1c28] rounded-full overflow-hidden">
            <div
              className={clsx('h-full rounded-full transition-all duration-500', scoreBarColor(score))}
              style={{ width: `${score}%` }}
            />
          </div>
          <div className="flex justify-between mt-1.5 text-[10px] text-gray-600 font-mono">
            <span>0 — LOW</span>
            <span>20 — MEDIUM</span>
            <span>50 — HIGH</span>
            <span>80 — CRITICAL</span>
          </div>
        </div>
      </div>

      {/* Scoring factors */}
      <div>
        <h2 className="text-sm font-semibold text-gray-200 mb-3">
          Scoring Breakdown
          <span className="ml-2 text-xs font-normal text-gray-500">
            (last 1 hour)
          </span>
        </h2>

        {dashboardLoading && !threat ? (
          <div className="card p-12 text-center">
            <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
            <p className="mt-3 text-sm text-gray-500">Loading threat data...</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <FactorCard
              icon={Activity}
              label="Event Volume"
              value={threat?.recent_events ?? 0}
              formula="log2(events + 1) &times; 2"
              points={volumePoints}
              maxDescription="Logarithmic scaling prevents volume spam"
            />
            <FactorCard
              icon={Users}
              label="Unique Attackers"
              value={threat?.unique_attackers ?? 0}
              formula="&radic;(unique IPs) &times; 4"
              points={breadthPoints}
              maxDescription="Diminishing returns per additional IP"
            />
            <FactorCard
              icon={Radio}
              label="Protocol Diversity"
              value={threat?.unique_protocols ?? 0}
              formula="unique protocols &times; 3"
              points={reconPoints}
              maxDescription="Multi-protocol probing signals recon"
            />
            <FactorCard
              icon={Flame}
              label="High Severity Events"
              value={threat?.high_severity_events ?? 0}
              formula="&radic;(capped events) &times; 3"
              points={severityPoints}
              maxDescription="Capped at 5 per IP, then sqrt scaled"
            />
          </div>
        )}
      </div>

      {/* How it works */}
      <div className="card p-5">
        <h2 className="text-sm font-semibold text-gray-200 mb-3">
          How Threat Level Works
        </h2>
        <div className="space-y-3 text-sm text-gray-400 leading-relaxed">
          <p>
            The threat level is recalculated every time the dashboard loads, based
            on honeypot activity from the <span className="text-gray-300 font-medium">last 1 hour</span>.
            It prioritises attack <span className="text-gray-300 font-medium">breadth and intent</span> over
            raw event volume, so a single bot brute-forcing SSH won&apos;t inflate the score
            the same way three different IPs probing multiple protocols would.
          </p>
          <p>
            The four components are summed into a composite score (capped at 100),
            then mapped to a level:
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
            {(
              [
                ['LOW', '0 – 19', 'text-green-400', 'bg-green-500/10 border-green-500/20'],
                ['MEDIUM', '20 – 49', 'text-yellow-400', 'bg-yellow-500/10 border-yellow-500/20'],
                ['HIGH', '50 – 79', 'text-orange-400', 'bg-orange-500/10 border-orange-500/20'],
                ['CRITICAL', '80 – 100', 'text-red-400', 'bg-red-500/10 border-red-500/20'],
              ] as const
            ).map(([label, range, textColor, bgColor]) => (
              <div
                key={label}
                className={clsx(
                  'rounded-lg border px-3 py-2 text-center',
                  bgColor
                )}
              >
                <p className={clsx('text-xs font-bold uppercase', textColor)}>
                  {label}
                </p>
                <p className="text-[11px] text-gray-500 font-mono mt-0.5">
                  {range}
                </p>
              </div>
            ))}
          </div>
          <p>
            High-severity events are capped at 5 per source IP before being scored,
            so a single noisy bot can contribute at most 7 severity points. Volume uses
            logarithmic scaling (log<sub>2</sub>) to provide diminishing returns — 100
            events scores about the same as 1,000.
          </p>
        </div>
      </div>
    </div>
  );
}
