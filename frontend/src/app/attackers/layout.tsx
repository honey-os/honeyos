'use client';

import React from 'react';
import AppShell from '@/components/shared/AppShell';

export default function AttackersLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppShell>{children}</AppShell>;
}
