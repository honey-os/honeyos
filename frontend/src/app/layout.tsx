import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });

export const metadata: Metadata = {
  title: 'HoneyOS - Network Deception & Intrusion Detection',
  description:
    'Open-source honeypot management and intrusion detection system with multi-protocol deception, session recording, and real-time alerts.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.variable} font-sans antialiased bg-[#0a0a0f] text-gray-200`}
      >
        {children}
      </body>
    </html>
  );
}
