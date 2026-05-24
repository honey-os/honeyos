'use client';

import React from 'react';
import { LucideIcon, TrendingUp, TrendingDown } from 'lucide-react';
import clsx from 'clsx';

interface MetricsCardProps {
  icon: LucideIcon;
  label: string;
  value: React.ReactNode;
  trend?: {
    value: number;
    label: string;
  };
  iconColor?: string;
  className?: string;
}

export default function MetricsCard({
  icon: Icon,
  label,
  value,
  trend,
  iconColor = 'text-amber-500',
  className,
}: MetricsCardProps) {
  const isPositiveTrend = trend && trend.value >= 0;

  return (
    <div
      className={clsx(
        'card p-5 flex flex-col gap-3 group hover:border-amber-500/20 transition-all duration-300',
        className
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className={clsx(
              'w-10 h-10 rounded-lg flex items-center justify-center',
              'bg-amber-500/10 group-hover:bg-amber-500/15 transition-colors'
            )}
          >
            <Icon className={clsx('w-5 h-5', iconColor)} />
          </div>
          <span className="text-sm font-medium text-gray-400">{label}</span>
        </div>
      </div>

      <div className="flex items-end justify-between">
        <span className="text-2xl font-bold text-gray-100 tracking-tight">
          {value}
        </span>

        {trend && (
          <div
            className={clsx(
              'flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-md',
              isPositiveTrend
                ? 'text-red-400 bg-red-500/10'
                : 'text-green-400 bg-green-500/10'
            )}
          >
            {isPositiveTrend ? (
              <TrendingUp className="w-3 h-3" />
            ) : (
              <TrendingDown className="w-3 h-3" />
            )}
            <span>
              {Math.abs(trend.value)}% {trend.label}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
