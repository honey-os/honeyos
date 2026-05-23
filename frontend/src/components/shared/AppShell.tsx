'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import clsx from 'clsx';
import {
  LayoutDashboard,
  Activity,
  Terminal,
  Hexagon,
  Shield,
  Bell,
  Globe,
  Settings,
  ChevronLeft,
  ChevronRight,
  Server,
} from 'lucide-react';
import { useStore } from '@/stores/useStore';

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

  return (
    <div className="flex h-screen overflow-hidden bg-[#0a0a0f]">
      {/* Sidebar */}
      <aside
        className={clsx(
          'flex flex-col border-r border-[#2a2a3a] bg-[#111118] transition-all duration-300 shrink-0',
          sidebarOpen ? 'w-60' : 'w-16'
        )}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-5 border-b border-[#2a2a3a]">
          <Link href="/" className="relative shrink-0">
            <Hexagon className="w-8 h-8 text-amber-500" />
            <Shield className="w-4 h-4 text-amber-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
          </Link>
          {sidebarOpen && (
            <Link href="/" className="text-lg font-bold text-gradient whitespace-nowrap">
              HoneyOS
            </Link>
          )}
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

        {/* Collapse toggle */}
        <div className="border-t border-[#2a2a3a] p-2">
          <button
            onClick={toggleSidebar}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-[#1c1c28] transition-colors text-sm"
          >
            {sidebarOpen ? (
              <>
                <ChevronLeft className="w-4 h-4" />
                <span>Collapse</span>
              </>
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
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
