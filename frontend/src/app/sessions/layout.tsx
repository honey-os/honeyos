'use client';

import React from 'react';
import AppShell from '@/components/shared/AppShell';

export default function SessionsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppShell>{children}</AppShell>;
}
