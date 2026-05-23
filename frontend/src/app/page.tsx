'use client';

import React from 'react';
import Link from 'next/link';
import {
  Shield,
  Terminal,
  Radio,
  Bell,
  Globe,
  Fingerprint,
  Server,
  ArrowRight,
  Hexagon,
} from 'lucide-react';

const features = [
  {
    icon: Terminal,
    title: 'Multi-Protocol Deception',
    description:
      'Deploy honeypots across SSH, HTTP, Telnet, FTP, MySQL, SMB, and RDP. Each protocol emulates realistic services to lure and study attackers.',
  },
  {
    icon: Radio,
    title: 'Session Recording',
    description:
      'Capture every keystroke, command, and file transfer. Replay attacker sessions with full fidelity to understand TTPs and attack patterns.',
  },
  {
    icon: Bell,
    title: 'Instant Alerts',
    description:
      'Get notified immediately via email, Slack, webhooks, or SMS when an intrusion is detected. Configurable thresholds and cooldown periods.',
  },
  {
    icon: Globe,
    title: 'WAN Monitoring',
    description:
      'Continuously scan your network perimeter to detect unauthorized services, open ports, and configuration drift before attackers do.',
  },
  {
    icon: Fingerprint,
    title: 'Zero False Positives',
    description:
      'Every interaction with a honeypot is by definition unauthorized. No tuning needed -- if someone touches it, they should not be there.',
  },
  {
    icon: Server,
    title: 'Fully Local',
    description:
      'Run entirely on your own hardware. No cloud dependencies, no data leaving your network. Perfect for air-gapped environments and Raspberry Pi deployments.',
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#0a0a0f] bg-grid relative">
      {/* Gradient overlay */}
      <div className="absolute inset-0 bg-gradient-to-b from-amber-500/5 via-transparent to-transparent pointer-events-none" />

      {/* Nav */}
      <nav className="relative z-10 border-b border-[#2a2a3a]/50">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Hexagon className="w-8 h-8 text-amber-500" />
              <Shield className="w-4 h-4 text-amber-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
            </div>
            <span className="text-xl font-bold text-gradient">HoneyOS</span>
          </div>
          <Link href="/dashboard" className="btn-primary flex items-center gap-2 text-sm">
            Go to Dashboard
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 pt-24 pb-20 text-center">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-amber-500/20 bg-amber-500/5 text-amber-400 text-sm font-medium mb-8">
          <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
          Open-source honeypot management
        </div>

        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight mb-6">
          <span className="text-gray-100">Honey</span>
          <span className="text-gradient">OS</span>
        </h1>

        <p className="text-xl sm:text-2xl text-gray-400 font-light mb-4 max-w-2xl mx-auto">
          Network Deception &amp; Intrusion Detection
        </p>

        <p className="text-base text-gray-500 max-w-xl mx-auto mb-12 leading-relaxed">
          Deploy intelligent honeypots across your network to catch attackers
          with zero false positives. Record sessions, analyze tactics, and get
          alerted the moment an intruder touches your traps.
        </p>

        <div className="flex items-center justify-center gap-4">
          <Link
            href="/dashboard"
            className="btn-primary flex items-center gap-2 text-base px-6 py-3"
          >
            Go to Dashboard
            <ArrowRight className="w-5 h-5" />
          </Link>
          <a
            href="https://github.com/honeyos"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary flex items-center gap-2 text-base px-6 py-3"
          >
            View on GitHub
          </a>
        </div>
      </section>

      {/* Features */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 pb-32">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature) => {
            const Icon = feature.icon;
            return (
              <div
                key={feature.title}
                className="card-hover p-6 group"
              >
                <div className="w-12 h-12 rounded-lg bg-amber-500/10 flex items-center justify-center mb-4 group-hover:bg-amber-500/15 transition-colors">
                  <Icon className="w-6 h-6 text-amber-500" />
                </div>
                <h3 className="text-lg font-semibold text-gray-100 mb-2">
                  {feature.title}
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {feature.description}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 border-t border-[#2a2a3a]/50 py-8">
        <div className="max-w-6xl mx-auto px-6 text-center text-sm text-gray-600">
          HoneyOS -- Open-source network deception platform
        </div>
      </footer>
    </div>
  );
}
