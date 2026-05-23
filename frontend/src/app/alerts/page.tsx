'use client';

import React, { useEffect, useState } from 'react';
import {
  Bell,
  Plus,
  X,
  Send,
  Power,
  PowerOff,
  Mail,
  Globe,
  MessageSquare,
  Smartphone,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import {
  createAlert,
  updateAlert,
  testAlert as testAlertApi,
} from '@/lib/api';
import type { Alert } from '@/lib/api';
import { formatDate, formatRelativeTime, formatNumber } from '@/utils/formatters';
import clsx from 'clsx';

const alertTypeIcons: Record<string, React.ElementType> = {
  email: Mail,
  webhook: Globe,
  slack: MessageSquare,
  sms: Smartphone,
};

const alertTypeLabels: Record<string, string> = {
  email: 'Email',
  webhook: 'Webhook',
  slack: 'Slack',
  sms: 'SMS',
};

interface AlertFormData {
  name: string;
  alert_type: string;
  enabled: boolean;
  config: Record<string, string>;
}

const configFieldsByType: Record<string, { key: string; label: string; placeholder: string; type?: string }[]> = {
  email: [
    { key: 'to_address', label: 'To Address', placeholder: 'admin@example.com' },
    { key: 'subject_prefix', label: 'Subject Prefix', placeholder: '[HoneyOS Alert]' },
  ],
  webhook: [
    { key: 'url', label: 'Webhook URL', placeholder: 'https://example.com/webhook' },
    { key: 'secret', label: 'Secret (optional)', placeholder: 'webhook-secret', type: 'password' },
  ],
  slack: [
    { key: 'webhook_url', label: 'Slack Webhook URL', placeholder: 'https://hooks.slack.com/services/...' },
    { key: 'channel', label: 'Channel', placeholder: '#security-alerts' },
  ],
  sms: [
    { key: 'phone_number', label: 'Phone Number', placeholder: '+1234567890' },
    { key: 'provider', label: 'Provider', placeholder: 'twilio' },
  ],
};

export default function AlertsPage() {
  const { alerts, alertsLoading, alertsError, fetchAlerts } = useStore();

  const [showAddModal, setShowAddModal] = useState(false);
  const [formData, setFormData] = useState<AlertFormData>({
    name: '',
    alert_type: 'email',
    enabled: true,
    config: {},
  });
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{
    id: string;
    success: boolean;
    message: string;
  } | null>(null);
  const [togglingId, setTogglingId] = useState<string | null>(null);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleToggle = async (alert: Alert) => {
    setTogglingId(alert.id);
    try {
      await updateAlert(alert.id, { enabled: !alert.enabled });
      await fetchAlerts();
    } catch (err) {
      console.error('Failed to toggle alert:', err);
    } finally {
      setTogglingId(null);
    }
  };

  const handleTest = async (alert: Alert) => {
    setTestingId(alert.id);
    setTestResult(null);
    try {
      const result = await testAlertApi(alert.id);
      setTestResult({ id: alert.id, ...result });
    } catch (err) {
      setTestResult({
        id: alert.id,
        success: false,
        message: err instanceof Error ? err.message : 'Test failed',
      });
    } finally {
      setTestingId(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await createAlert({
        name: formData.name,
        alert_type: formData.alert_type,
        enabled: formData.enabled,
        config: formData.config,
      });
      await fetchAlerts();
      setShowAddModal(false);
      setFormData({ name: '', alert_type: 'email', enabled: true, config: {} });
    } catch (err) {
      console.error('Failed to create alert:', err);
    } finally {
      setSaving(false);
    }
  };

  const configFields = configFieldsByType[formData.alert_type] || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Alerts</h1>
          <p className="text-sm text-gray-500 mt-1">
            Configure notification channels for intrusion alerts
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="btn-primary flex items-center gap-2 text-sm"
        >
          <Plus className="w-4 h-4" />
          Add Alert
        </button>
      </div>

      {/* Error */}
      {alertsError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {alertsError}
        </div>
      )}

      {/* Loading */}
      {alertsLoading && alerts.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="mt-3 text-sm text-gray-500">Loading alerts...</p>
        </div>
      ) : alerts.length === 0 ? (
        <div className="card p-12 text-center">
          <Bell className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400 mb-2">
            No alerts configured
          </h3>
          <p className="text-sm text-gray-600 mb-6">
            Set up notification channels to be alerted when intrusions are detected.
          </p>
          <button
            onClick={() => setShowAddModal(true)}
            className="btn-primary inline-flex items-center gap-2 text-sm"
          >
            <Plus className="w-4 h-4" />
            Add Alert
          </button>
        </div>
      ) : (
        /* Alert list */
        <div className="space-y-3">
          {alerts.map((alert) => {
            const TypeIcon =
              alertTypeIcons[alert.alert_type] || Bell;
            const typeLabel =
              alertTypeLabels[alert.alert_type] || alert.alert_type;
            const tr = testResult?.id === alert.id ? testResult : null;

            return (
              <div
                key={alert.id}
                className={clsx(
                  'card p-5 transition-all duration-200',
                  alert.enabled
                    ? 'border-[#2a2a3a] hover:border-amber-500/20'
                    : 'border-[#2a2a3a]/50 opacity-60'
                )}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-4">
                    <div
                      className={clsx(
                        'w-10 h-10 rounded-lg flex items-center justify-center',
                        alert.enabled
                          ? 'bg-amber-500/10 text-amber-500'
                          : 'bg-gray-500/10 text-gray-600'
                      )}
                    >
                      <TypeIcon className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold text-gray-100">
                          {alert.name}
                        </h3>
                        <span className="px-2 py-0.5 rounded-md text-xs font-medium bg-[#1c1c28] text-gray-400 border border-[#2a2a3a]">
                          {typeLabel}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                        <span>
                          Sent {formatNumber(alert.send_count)} times
                        </span>
                        <span>
                          Last sent:{' '}
                          {alert.last_sent
                            ? formatRelativeTime(alert.last_sent)
                            : 'Never'}
                        </span>
                      </div>

                      {/* Config summary */}
                      {alert.config && (
                        <div className="mt-2 text-xs text-gray-600 font-mono">
                          {Object.entries(alert.config as Record<string, string>)
                            .filter(([k]) => k !== 'secret' && k !== 'password')
                            .map(([k, v]) => (
                              <span key={k} className="mr-3">
                                {k}: {String(v)}
                              </span>
                            ))}
                        </div>
                      )}

                      {/* Test result */}
                      {tr && (
                        <div
                          className={clsx(
                            'mt-2 flex items-center gap-2 text-xs',
                            tr.success ? 'text-green-400' : 'text-red-400'
                          )}
                        >
                          {tr.success ? (
                            <CheckCircle className="w-3.5 h-3.5" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5" />
                          )}
                          {tr.message}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleTest(alert)}
                      disabled={testingId === alert.id || !alert.enabled}
                      className="btn-secondary flex items-center gap-1.5 text-xs disabled:opacity-40"
                    >
                      <Send className="w-3.5 h-3.5" />
                      {testingId === alert.id ? 'Testing...' : 'Test'}
                    </button>
                    <button
                      onClick={() => handleToggle(alert)}
                      disabled={togglingId === alert.id}
                      className={clsx(
                        'p-2 rounded-md transition-colors',
                        alert.enabled
                          ? 'text-green-400 hover:bg-green-500/10'
                          : 'text-gray-600 hover:bg-gray-500/10'
                      )}
                      title={alert.enabled ? 'Disable' : 'Enable'}
                    >
                      {alert.enabled ? (
                        <Power className="w-4 h-4" />
                      ) : (
                        <PowerOff className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Add alert modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="card max-w-lg w-full p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-gray-100">
                Add New Alert
              </h2>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-gray-500 hover:text-gray-300 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="label-text">Alert Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                  className="input-field w-full"
                  placeholder="Security Team Email"
                  required
                />
              </div>

              <div>
                <label className="label-text">Alert Type</label>
                <div className="grid grid-cols-4 gap-2">
                  {Object.entries(alertTypeLabels).map(([type, label]) => {
                    const TypeIcon = alertTypeIcons[type] || Bell;
                    return (
                      <button
                        key={type}
                        type="button"
                        onClick={() =>
                          setFormData({
                            ...formData,
                            alert_type: type,
                            config: {},
                          })
                        }
                        className={clsx(
                          'flex flex-col items-center gap-1.5 p-3 rounded-lg border text-sm transition-all',
                          formData.alert_type === type
                            ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                            : 'border-[#2a2a3a] text-gray-500 hover:text-gray-300 hover:bg-[#1c1c28]'
                        )}
                      >
                        <TypeIcon className="w-5 h-5" />
                        {label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Dynamic config fields */}
              {configFields.map((field) => (
                <div key={field.key}>
                  <label className="label-text">{field.label}</label>
                  <input
                    type={field.type || 'text'}
                    value={(formData.config[field.key] as string) || ''}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        config: {
                          ...formData.config,
                          [field.key]: e.target.value,
                        },
                      })
                    }
                    className="input-field w-full"
                    placeholder={field.placeholder}
                  />
                </div>
              ))}

              <div className="flex items-center gap-3">
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.enabled}
                    onChange={(e) =>
                      setFormData({ ...formData, enabled: e.target.checked })
                    }
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-gray-700 rounded-full peer peer-checked:bg-amber-500 transition-colors after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-full" />
                </label>
                <span className="text-sm text-gray-300">
                  Enable immediately
                </span>
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  type="submit"
                  disabled={saving}
                  className="btn-primary flex items-center gap-2 text-sm disabled:opacity-50"
                >
                  {saving ? 'Creating...' : 'Create Alert'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="btn-secondary text-sm"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
