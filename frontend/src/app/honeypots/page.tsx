'use client';

import React, { useEffect, useState } from 'react';
import {
  Server,
  X,
  Power,
  PowerOff,
  Settings,
  Terminal,
  Globe,
  Database,
  Monitor,
  Network,
  HardDrive,
  Wifi,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import { updateHoneypot, deleteHoneypot } from '@/lib/api';
import type { Honeypot } from '@/lib/api';
import { formatDate, formatRelativeTime, formatNumber } from '@/utils/formatters';
import clsx from 'clsx';

const protocolIcons: Record<string, React.ElementType> = {
  ssh: Terminal,
  http: Globe,
  https: Globe,
  telnet: Monitor,
  ftp: HardDrive,
  mysql: Database,
  smb: Network,
  rdp: Monitor,
  dns: Wifi,
};

const protocolColors: Record<string, string> = {
  ssh: 'text-emerald-400 bg-emerald-500/10',
  http: 'text-blue-400 bg-blue-500/10',
  https: 'text-blue-400 bg-blue-500/10',
  telnet: 'text-purple-400 bg-purple-500/10',
  ftp: 'text-cyan-400 bg-cyan-500/10',
  mysql: 'text-orange-400 bg-orange-500/10',
  smb: 'text-rose-400 bg-rose-500/10',
  rdp: 'text-indigo-400 bg-indigo-500/10',
  dns: 'text-teal-400 bg-teal-500/10',
};

export default function HoneypotsPage() {
  const {
    honeypots,
    honeypotsLoading,
    honeypotsError,
    fetchHoneypots,
  } = useStore();

  const [showAddModal, setShowAddModal] = useState(false);
  const [editingHoneypot, setEditingHoneypot] = useState<Honeypot | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    protocol: 'ssh',
    port: 2222,
    description: '',
    enabled: true,
  });
  const [saving, setSaving] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);

  useEffect(() => {
    fetchHoneypots();
  }, [fetchHoneypots]);

  const handleToggle = async (honeypot: Honeypot) => {
    setTogglingId(honeypot.id);
    try {
      await updateHoneypot(honeypot.id, { enabled: !honeypot.enabled });
      await fetchHoneypots();
    } catch (err) {
      console.error('Failed to toggle honeypot:', err);
    } finally {
      setTogglingId(null);
    }
  };

  const handleDelete = async (honeypot: Honeypot) => {
    if (!confirm(`Delete honeypot "${honeypot.name}"? This cannot be undone.`)) {
      return;
    }
    try {
      await deleteHoneypot(honeypot.id);
      await fetchHoneypots();
    } catch (err) {
      console.error('Failed to delete honeypot:', err);
    }
  };

  const openEditModal = (honeypot: Honeypot) => {
    setEditingHoneypot(honeypot);
    setFormData({
      name: honeypot.name,
      protocol: honeypot.protocol,
      port: honeypot.port,
      description: honeypot.description || '',
      enabled: honeypot.enabled,
    });
    setShowAddModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      if (editingHoneypot) {
        await updateHoneypot(editingHoneypot.id, formData);
      }
      await fetchHoneypots();
      setShowAddModal(false);
    } catch (err) {
      console.error('Failed to save honeypot:', err);
    } finally {
      setSaving(false);
    }
  };

  const defaultPorts: Record<string, number> = {
    ssh: 2222,
    http: 8080,
    telnet: 2323,
    ftp: 2121,
    mysql: 3307,
    smb: 4450,
    rdp: 3390,
    dns: 5353,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Honeypots</h1>
          <p className="text-sm text-gray-500 mt-1">
            Manage your deception services
          </p>
        </div>
      </div>

      {/* Error */}
      {honeypotsError && (
        <div className="card p-4 border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          {honeypotsError}
        </div>
      )}

      {/* Loading */}
      {honeypotsLoading && honeypots.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="inline-block w-6 h-6 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="mt-3 text-sm text-gray-500">Loading honeypots...</p>
        </div>
      ) : honeypots.length === 0 ? (
        <div className="card p-12 text-center">
          <Server className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400 mb-2">
            No honeypots configured
          </h3>
          <p className="text-sm text-gray-600">
            Deploy your first deception service to start catching intruders.
          </p>
        </div>
      ) : (
        /* Honeypot grid */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {honeypots.map((honeypot) => {
            const IconComp =
              protocolIcons[honeypot.protocol.toLowerCase()] || Server;
            const colorClass =
              protocolColors[honeypot.protocol.toLowerCase()] ||
              'text-gray-400 bg-gray-500/10';

            return (
              <div
                key={honeypot.id}
                className={clsx(
                  'card p-5 relative group transition-all duration-300',
                  honeypot.enabled
                    ? 'border-[#2a2a3a] hover:border-amber-500/20'
                    : 'border-[#2a2a3a]/50 opacity-60'
                )}
              >
                {/* Status indicator */}
                <div className="absolute top-4 right-4 flex items-center gap-2">
                  <button
                    onClick={() => handleToggle(honeypot)}
                    disabled={togglingId === honeypot.id}
                    className={clsx(
                      'p-1.5 rounded-md transition-colors',
                      honeypot.enabled
                        ? 'text-green-400 hover:bg-green-500/10'
                        : 'text-gray-600 hover:bg-gray-500/10'
                    )}
                    title={honeypot.enabled ? 'Disable' : 'Enable'}
                  >
                    {honeypot.enabled ? (
                      <Power className="w-4 h-4" />
                    ) : (
                      <PowerOff className="w-4 h-4" />
                    )}
                  </button>
                  <button
                    onClick={() => openEditModal(honeypot)}
                    className="p-1.5 rounded-md text-gray-600 hover:text-gray-300 hover:bg-gray-500/10 transition-colors"
                    title="Edit"
                  >
                    <Settings className="w-4 h-4" />
                  </button>
                </div>

                {/* Protocol icon & name */}
                <div className="flex items-center gap-3 mb-4">
                  <div
                    className={clsx(
                      'w-12 h-12 rounded-lg flex items-center justify-center',
                      colorClass
                    )}
                  >
                    <IconComp className="w-6 h-6" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-100">
                      {honeypot.name}
                    </h3>
                    <span className="text-xs font-mono text-gray-500 uppercase">
                      {honeypot.protocol}
                    </span>
                  </div>
                </div>

                {/* Info */}
                <div className="space-y-2 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Port</span>
                    <span className="font-mono text-gray-300">
                      {honeypot.port}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Status</span>
                    <span
                      className={
                        honeypot.enabled ? 'text-green-400' : 'text-gray-600'
                      }
                    >
                      {honeypot.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Interactions</span>
                    <span className="font-mono text-gray-300">
                      {formatNumber(honeypot.total_interactions)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">Last Activity</span>
                    <span className="text-gray-400 text-xs">
                      {honeypot.last_activity
                        ? formatRelativeTime(honeypot.last_activity)
                        : 'Never'}
                    </span>
                  </div>
                </div>

                {honeypot.description && (
                  <p className="text-xs text-gray-600 mt-3 border-t border-[#2a2a3a] pt-3">
                    {honeypot.description}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Add/Edit modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="card max-w-lg w-full p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-gray-100">
                Edit Honeypot
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
                <label className="label-text">Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                  className="input-field w-full"
                  placeholder="SSH Honeypot"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label-text">Protocol</label>
                  <select
                    value={formData.protocol}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        protocol: e.target.value,
                        port:
                          defaultPorts[e.target.value] || formData.port,
                      })
                    }
                    className="select-field w-full"
                  >
                    {Object.keys(protocolIcons).map((p) => (
                      <option key={p} value={p}>
                        {p.toUpperCase()}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="label-text">Port</label>
                  <input
                    type="number"
                    value={formData.port}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        port: parseInt(e.target.value) || 0,
                      })
                    }
                    className="input-field w-full"
                    min={1}
                    max={65535}
                    required
                  />
                </div>
              </div>

              <div>
                <label className="label-text">Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) =>
                    setFormData({ ...formData, description: e.target.value })
                  }
                  className="input-field w-full"
                  rows={3}
                  placeholder="Optional description..."
                />
              </div>

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
                  {saving ? 'Saving...' : 'Update'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="btn-secondary text-sm"
                >
                  Cancel
                </button>
                {editingHoneypot && (
                  <button
                    type="button"
                    onClick={() => {
                      handleDelete(editingHoneypot);
                      setShowAddModal(false);
                    }}
                    className="btn-danger text-sm ml-auto"
                  >
                    Delete
                  </button>
                )}
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
