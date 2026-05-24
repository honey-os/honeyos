'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import clsx from 'clsx';
import Image from 'next/image';
import {
  LayoutDashboard,
  Activity,
  Terminal,
  Bell,
  Globe,
  Settings,
  ChevronLeft,
  ChevronRight,
  Server,
  LogOut,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';
import { authLogout } from '@/lib/api';

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/events', label: 'Events', icon: Activity },
  { href: '/sessions', label: 'Sessions', icon: Terminal },
  { href: '/honeypots', label: 'Honeypots', icon: Server },
  { href: '/alerts', label: 'Alerts', icon: Bell },
  { href: '/network', label: 'Network', icon: Globe },
  { href: '/settings', label: 'Settings', icon: Settings },
];

interface AppShellProps {
  children: React.ReactNode;
}

export default function AppShell({ children }: AppShellProps) {
  const pathname = usePathname();
  const sidebarOpen = useStore((s) => s.sidebarOpen);
  const toggleSidebar = useStore((s) => s.toggleSidebar);
  const setSelectedSession = useStore((s) => s.setSelectedSession);

  return (
    <div className="flex h-screen overflow-hidden bg-[#0a0a0f]">
      {/* Sidebar */}
      <aside
        className={clsx(
          'flex flex-col border-r border-[#2a2a3a] bg-[#111118] transition-all duration-300 shrink-0',
          sidebarOpen ? 'w-60' : 'w-16'
        )}
      >
        {/* Logo + collapse toggle */}
        <div className="flex items-center justify-between px-4 py-5 border-b border-[#2a2a3a]">
          <div className="flex items-center gap-3">
            <Link href="/" className="shrink-0">
              <Image
                src="/images/logo-icon.png"
                alt="HoneyOS"
                width={32}
                height={32}
              />
            </Link>
            {sidebarOpen && (
              <Link href="/" className="shrink-0">
                <Image
                  src="/images/logo-text-white.png"
                  alt="HoneyOS"
                  width={110}
                  height={26}
                />
              </Link>
            )}
          </div>
          <button
            onClick={toggleSidebar}
            className="p-1 rounded text-gray-500 hover:text-gray-300 hover:bg-[#1c1c28] transition-colors"
            title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {sidebarOpen ? (
              <ChevronLeft className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href;

            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => {
                  if (item.href === '/sessions') setSelectedSession(null);
                }}
                className={clsx(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200',
                  isActive
                    ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-[#1c1c28] border border-transparent'
                )}
                title={!sidebarOpen ? item.label : undefined}
              >
                <Icon className={clsx('w-5 h-5 shrink-0', isActive && 'text-amber-500')} />
                {sidebarOpen && <span>{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Sign out */}
        <div className="border-t border-[#2a2a3a] p-2">
          <button
            onClick={async () => {
              await authLogout();
              window.location.reload();
            }}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-gray-500 hover:text-red-400 hover:bg-[#1c1c28] transition-colors text-sm"
            title={!sidebarOpen ? 'Sign Out' : undefined}
          >
            <LogOut className="w-4 h-4 shrink-0" />
            {sidebarOpen && <span>Sign Out</span>}
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <div className="p-6 lg:p-8">{children}</div>
      </main>
    </div>
  );
}
