'use client';

import React, { useEffect, useState } from 'react';
import {
  Settings,
  Server,
  Lock,
  CheckCircle,
  AlertTriangle,
  Clock,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import { authChangePassword } from '@/lib/api';
import type { SettingsSection } from '@/lib/api';
import clsx from 'clsx';

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function SettingValue({ value, type }: { value: string; type: string }) {
  if (value === 'Not configured') {
    return <span className="text-gray-600 italic">Not configured</span>;
  }

  if (type === 'bool') {
    const enabled = value === 'true';
    return (
      <span
        className={clsx(
          'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium',
          enabled
            ? 'bg-green-500/10 text-green-400 border border-green-500/20'
            : 'bg-gray-500/10 text-gray-500 border border-gray-500/20'
        )}
      >
        {enabled ? 'Enabled' : 'Disabled'}
      </span>
    );
  }

  return <span className="text-gray-300 font-mono text-sm">{value}</span>;
}

function SectionCard({ section }: { section: SettingsSection }) {
  return (
    <div className="card">
      <div className="px-5 py-4 border-b border-[#2a2a3a]">
        <h3 className="text-sm font-semibold text-gray-200">
          {section.label}
        </h3>
      </div>
      <div className="px-5 divide-y divide-[#2a2a3a]/50">
        {section.settings.map((setting) => (
          <div
            key={setting.key}
            className="flex items-center justify-between gap-4 py-3"
          >
            <div className="flex-1 min-w-0">
              <span className="text-sm text-gray-400">{setting.label}</span>
              <span className="text-xs text-gray-700 font-mono ml-2">
                {setting.key}
              </span>
            </div>
            <div className="shrink-0">
              <SettingValue value={setting.value} type={setting.type} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const { settings, settingsLoading, settingsError, fetchSettings } =
    useStore();

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
          <Settings className="w-6 h-6 text-amber-500" />
          Settings
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Configuration is managed via the <code className="text-amber-500/80 bg-amber-500/5 px-1.5 py-0.5 rounded text-xs">.env</code> file. Values shown here are read-only.
        </p>
      </div>

      {/* Error */}
      {settingsError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          {settingsError}
        </div>
      )}

      {/* Loading */}
      {settingsLoading && !settings ? (
        <div className="card p-12 text-center">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="mt-3 text-sm text-gray-500">Loading settings...</p>
        </div>
      ) : settings ? (
        <div className="space-y-6">
          {/* Config sections */}
          {settings.sections.map((section) => (
            <SectionCard key={section.id} section={section} />
          ))}

          {/* System Information */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-gray-200 mb-4 flex items-center gap-2">
              <Server className="w-4 h-4 text-amber-500" />
              System Information
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-3 rounded-lg bg-[#0a0a0f] border border-[#2a2a3a]">
                <span className="text-xs text-gray-600 uppercase tracking-wider">
                  Version
                </span>
                <p className="text-sm font-mono text-gray-300 mt-1">
                  HoneyOS v{settings.system.version}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-[#0a0a0f] border border-[#2a2a3a]">
                <span className="text-xs text-gray-600 uppercase tracking-wider">
                  Database
                </span>
                <p className="text-sm font-mono text-gray-300 mt-1">
                  {settings.system.database}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-[#0a0a0f] border border-[#2a2a3a]">
                <span className="text-xs text-gray-600 uppercase tracking-wider">
                  Uptime
                </span>
                <p className="text-sm font-mono text-gray-300 mt-1 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-gray-600" />
                  {formatUptime(settings.system.uptime_seconds)}
                </p>
              </div>
            </div>
          </div>

          {/* Change Password */}
          <ChangePasswordSection />
        </div>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Change Password Section
// ---------------------------------------------------------------------------

function ChangePasswordSection() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setResult(null);

    if (newPassword.length < 8) {
      setResult({ success: false, message: 'New password must be at least 8 characters' });
      return;
    }
    if (newPassword !== confirmPassword) {
      setResult({ success: false, message: 'New passwords do not match' });
      return;
    }

    setSaving(true);
    try {
      await authChangePassword(currentPassword, newPassword);
      setResult({ success: true, message: 'Password changed successfully' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setResult({
        success: false,
        message: err instanceof Error ? err.message : 'Failed to change password',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card p-5">
      <h3 className="text-sm font-semibold text-gray-200 mb-4 flex items-center gap-2">
        <Lock className="w-4 h-4 text-amber-500" />
        Change Password
      </h3>
      <form onSubmit={handleChangePassword} className="space-y-4 max-w-md">
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1.5">
            Current Password
          </label>
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            className="input-field w-full text-sm"
            placeholder="Enter current password"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1.5">
            New Password
          </label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="input-field w-full text-sm"
            placeholder="Minimum 8 characters"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1.5">
            Confirm New Password
          </label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="input-field w-full text-sm"
            placeholder="Re-enter new password"
          />
        </div>

        {result && (
          <div
            className={clsx(
              'flex items-center gap-2 text-sm px-3 py-2 rounded-lg border',
              result.success
                ? 'border-green-500/30 bg-green-500/5 text-green-400'
                : 'border-red-500/30 bg-red-500/5 text-red-400'
            )}
          >
            {result.success ? (
              <CheckCircle className="w-4 h-4 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0" />
            )}
            {result.message}
          </div>
        )}

        <button
          type="submit"
          disabled={saving}
          className="btn-primary text-sm disabled:opacity-50"
        >
          {saving ? 'Changing...' : 'Change Password'}
        </button>
      </form>
    </div>
  );
}
