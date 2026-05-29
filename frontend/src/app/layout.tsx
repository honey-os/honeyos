import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import Script from 'next/script';
import './globals.css';
import AuthGate from '@/components/shared/AuthGate';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

export const metadata: Metadata = {
  title: 'HoneyOS - Network Deception & Intrusion Detection',
  description:
    'Open-source honeypot management and intrusion detection system with multi-protocol deception, session recording, and real-time alerts.',
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: 'any' },
      { url: '/favicon-16x16.png', sizes: '16x16', type: 'image/png' },
      { url: '/favicon-32x32.png', sizes: '32x32', type: 'image/png' },
    ],
    apple: '/apple-touch-icon.png',
  },
  manifest: '/site.webmanifest',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Runtime API URL override — NOT a NEXT_PUBLIC_ var, so it's read at
  // request time by this server component rather than baked in at build.
  const apiUrl = process.env.API_URL || '';

  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.variable} font-sans antialiased bg-[#0a0a0f] text-gray-200`}
      >
        {apiUrl && (
          <Script
            id="honeyos-config"
            strategy="beforeInteractive"
            dangerouslySetInnerHTML={{
              __html: `window.__HONEYOS_API_URL__=${JSON.stringify(apiUrl)};`,
            }}
          />
        )}
        <AuthGate>{children}</AuthGate>
      </body>
    </html>
  );
}
