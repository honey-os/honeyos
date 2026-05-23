'use client';

import React, { useEffect, useState } from 'react';
import {
  Settings,
  Save,
  Download,
  Upload,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  Server,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import {
  updateConfig,
  exportConfig,
  importConfig,
} from '@/lib/api';
import type { SystemConfigItem } from '@/lib/api';
import clsx from 'clsx';

const configSections: Record<string, { label: string; keys: string[] }> = {
  general: {
    label: 'General',
    keys: [
      'SECRET_KEY',
      'DEBUG',
      'LOG_LEVEL',
    ],
  },
  network: {
    label: 'Network',
    keys: [
      'NETWORK_INTERFACE',
      'PORT_RANGE_START',
      'PORT_RANGE_END',
      'BIND_HOST',
      'API_PORT',
    ],
  },
  alerts: {
    label: 'Alerts',
    keys: [
      'SMTP_HOST',
      'SMTP_PORT',
      'SMTP_USERNAME',
      'SMTP_FROM_ADDRESS',
      'SMTP_USE_TLS',
      'SLACK_WEBHOOK_URL',
      'ALERT_COOLDOWN_SECONDS',
    ],
  },
  retention: {
    label: 'Data Retention',
    keys: ['RETENTION_DAYS'],
  },
  honeypots: {
    label: 'Honeypot Ports',
    keys: [
      'SSH_HONEYPOT_PORT',
      'HTTP_HONEYPOT_PORT',
      'TELNET_HONEYPOT_PORT',
      'FTP_HONEYPOT_PORT',
      'MYSQL_HONEYPOT_PORT',
    ],
  },
};

export default function SettingsPage() {
  const { config, configLoading, configError, fetchConfig } = useStore();

  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saveResult, setSaveResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  useEffect(() => {
    const values: Record<string, string> = {};
    config.forEach((item) => {
      values[item.key] = item.value || '';
    });
    setFormValues(values);
  }, [config]);

  const handleChange = (key: string, value: string) => {
    setFormValues((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveResult(null);
    try {
      await updateConfig(formValues);
      setSaveResult({ success: true, message: 'Configuration saved successfully' });
      await fetchConfig();
    } catch (err) {
      setSaveResult({
        success: false,
        message: err instanceof Error ? err.message : 'Failed to save configuration',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleExport = async () => {
    try {
      const data = await exportConfig();
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `honeyos-config-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  const handleImport = async () => {
    setImportError(null);
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;

      try {
        const text = await file.text();
        const data = JSON.parse(text);
        await importConfig(data);
        await fetchConfig();
        setSaveResult({
          success: true,
          message: 'Configuration imported successfully',
        });
      } catch (err) {
        setImportError(
          err instanceof Error ? err.message : 'Failed to import configuration'
        );
      }
    };
    input.click();
  };

  const getConfigItem = (key: string): SystemConfigItem | undefined => {
    return config.find((c) => c.key === key);
  };

  const renderField = (key: string) => {
    const item = getConfigItem(key);
    const value = formValues[key] || '';
    const configType = item?.config_type || 'string';
    const description = item?.description;

    const isBool = configType === 'bool' || value === 'true' || value === 'false';
    const isNumber = configType === 'int' || configType === 'number';
    const isPassword = key.toLowerCase().includes('password') || key.toLowerCase().includes('secret');

    return (
      <div key={key} className="flex items-start justify-between gap-4 py-3">
        <div className="flex-1 min-w-0">
          <label className="text-sm font-medium text-gray-300 font-mono">
            {key}
          </label>
          {description && (
            <p className="text-xs text-gray-600 mt-0.5">{description}</p>
          )}
        </div>
        <div className="w-64 shrink-0">
          {isBool ? (
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={value === 'true'}
                onChange={(e) =>
                  handleChange(key, e.target.checked ? 'true' : 'false')
                }
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-gray-700 rounded-full peer peer-checked:bg-amber-500 transition-colors after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full" />
            </label>
          ) : isNumber ? (
            <input
              type="number"
              value={value}
              onChange={(e) => handleChange(key, e.target.value)}
              className="input-field w-full text-sm"
            />
          ) : (
            <input
              type={isPassword ? 'password' : 'text'}
              value={value}
              onChange={(e) => handleChange(key, e.target.value)}
              className="input-field w-full text-sm"
              placeholder={item?.description || ''}
            />
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Settings</h1>
          <p className="text-sm text-gray-500 mt-1">
            System configuration and preferences
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleExport}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          <button
            onClick={handleImport}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <Upload className="w-4 h-4" />
            Import
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="btn-primary flex items-center gap-2 text-sm disabled:opacity-50"
          >
            {saving ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>

      {/* Save result */}
      {saveResult && (
        <div
          className={clsx(
            'card p-4 flex items-center gap-2 text-sm',
            saveResult.success
              ? 'border-green-500/30 bg-green-500/5 text-green-400'
              : 'border-red-500/30 bg-red-500/5 text-red-400'
          )}
        >
          {saveResult.success ? (
            <CheckCircle className="w-4 h-4" />
          ) : (
            <AlertTriangle className="w-4 h-4" />
          )}
          {saveResult.message}
        </div>
      )}

      {/* Import error */}
      {importError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          {importError}
        </div>
      )}

      {/* Config error */}
      {configError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {configError}
        </div>
      )}

      {/* Loading */}
      {configLoading && config.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="mt-3 text-sm text-gray-500">Loading configuration...</p>
        </div>
      ) : (
        /* Config sections */
        <div className="space-y-6">
          {Object.entries(configSections).map(([sectionKey, section]) => {
            const sectionKeys = section.keys.filter(
              (k) => formValues[k] !== undefined || getConfigItem(k)
            );

            if (sectionKeys.length === 0 && config.length > 0) {
              // Show all keys for this section even if not in config yet
              return (
                <div key={sectionKey} className="card">
                  <div className="px-5 py-4 border-b border-[#2a2a3a]">
                    <h3 className="text-sm font-semibold text-gray-200">
                      {section.label}
                    </h3>
                  </div>
                  <div className="px-5 divide-y divide-[#2a2a3a]/50">
                    {section.keys.map((key) => renderField(key))}
                  </div>
                </div>
              );
            }

            return (
              <div key={sectionKey} className="card">
                <div className="px-5 py-4 border-b border-[#2a2a3a]">
                  <h3 className="text-sm font-semibold text-gray-200">
                    {section.label}
                  </h3>
                </div>
                <div className="px-5 divide-y divide-[#2a2a3a]/50">
                  {section.keys.map((key) => renderField(key))}
                </div>
              </div>
            );
          })}

          {/* Uncategorized settings */}
          {config.length > 0 && (() => {
            const allSectionKeys = new Set(
              Object.values(configSections).flatMap((s) => s.keys)
            );
            const uncategorized = config.filter(
              (c) => !allSectionKeys.has(c.key)
            );

            if (uncategorized.length === 0) return null;

            return (
              <div className="card">
                <div className="px-5 py-4 border-b border-[#2a2a3a]">
                  <h3 className="text-sm font-semibold text-gray-200">
                    Other
                  </h3>
                </div>
                <div className="px-5 divide-y divide-[#2a2a3a]/50">
                  {uncategorized.map((item) => renderField(item.key))}
                </div>
              </div>
            );
          })()}

          {/* System info */}
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
                  HoneyOS v0.1.0
                </p>
              </div>
              <div className="p-3 rounded-lg bg-[#0a0a0f] border border-[#2a2a3a]">
                <span className="text-xs text-gray-600 uppercase tracking-wider">
                  Database
                </span>
                <p className="text-sm font-mono text-gray-300 mt-1">SQLite</p>
              </div>
              <div className="p-3 rounded-lg bg-[#0a0a0f] border border-[#2a2a3a]">
                <span className="text-xs text-gray-600 uppercase tracking-wider">
                  Config Items
                </span>
                <p className="text-sm font-mono text-gray-300 mt-1">
                  {config.length}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
