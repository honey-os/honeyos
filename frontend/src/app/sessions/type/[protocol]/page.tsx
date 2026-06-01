'use client';

import { useParams } from 'next/navigation';
import SessionsList from '../../SessionsList';

export default function SessionsByProtocolPage() {
  const { protocol } = useParams<{ protocol: string }>();
  return <SessionsList pathProtocol={protocol} />;
}
