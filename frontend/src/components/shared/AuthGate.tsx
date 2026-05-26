'use client';

import React, { useEffect, useState } from 'react';
import Image from 'next/image';
import { getAuthStatus, authSetup, authLogin } from '@/lib/api';

type AuthState = 'loading' | 'needs_setup' | 'needs_login' | 'authenticated';

export default function AuthGate({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>('loading');

  useEffect(() => {
    checkAuth();
  }, []);

  async function checkAuth() {
    try {
      const status = await getAuthStatus();
      if (!status.has_admin) {
        setState('needs_setup');
      } else if (!status.authenticated) {
        setState('needs_login');
      } else {
        setState('authenticated');
      }
    } catch {
      setState('needs_login');
    }
  }

  if (state === 'loading') {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#0a0a0f]">
        <div className="inline-block w-8 h-8 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
      </div>
    );
  }

  if (state === 'needs_setup') {
    return <SetupScreen onComplete={() => setState('authenticated')} />;
  }

  if (state === 'needs_login') {
    return <LoginScreen onComplete={() => setState('authenticated')} />;
  }

  return <>{children}</>;
}

// ---------------------------------------------------------------------------
// Setup Screen
// ---------------------------------------------------------------------------

function SetupScreen({ onComplete }: { onComplete: () => void }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      await authSetup(password);
      onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-[#0a0a0f] px-4">
      <div className="card w-full max-w-md p-8">
        <div className="flex flex-col items-center mb-8">
          <Image
            src="/images/logo-icon.png"
            alt="HoneyOS"
            width={48}
            height={48}
            className="mb-4"
          />
          <Image
            src="/images/logo-text-white.png"
            alt="HoneyOS"
            width={140}
            height={32}
          />
          <h1 className="text-xl font-semibold text-gray-100 mt-6">
            Welcome to HoneyOS
          </h1>
          <p className="text-sm text-gray-500 mt-2 text-center">
            Create a password to secure your dashboard.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input-field w-full"
              placeholder="Minimum 8 characters"
              autoFocus
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">
              Confirm Password
            </label>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="input-field w-full"
              placeholder="Re-enter password"
            />
          </div>

          {error && (
            <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full text-sm disabled:opacity-50"
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Login Screen
// ---------------------------------------------------------------------------

function LoginScreen({ onComplete }: { onComplete: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await authLogin(password);
      onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-[#0a0a0f] px-4">
      <div className="card w-full max-w-md p-8">
        <div className="flex flex-col items-center mb-8">
          <Image
            src="/images/logo-icon.png"
            alt="HoneyOS"
            width={48}
            height={48}
            className="mb-4"
          />
          <Image
            src="/images/logo-text-white.png"
            alt="HoneyOS"
            width={140}
            height={32}
          />
          <h1 className="text-xl font-semibold text-gray-100 mt-6">
            Sign In
          </h1>
          <p className="text-sm text-gray-500 mt-2">
            Enter your password to access the dashboard.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1.5">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input-field w-full"
              placeholder="Enter your password"
              autoFocus
            />
          </div>

          {error && (
            <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full text-sm disabled:opacity-50"
          >
            {loading ? 'Signing In...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
