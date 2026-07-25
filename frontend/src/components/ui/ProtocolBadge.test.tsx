import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import ProtocolBadge from './ProtocolBadge';

describe('ProtocolBadge', () => {
  it('renders the protocol label verbatim', () => {
    render(<ProtocolBadge protocol="ssh" />);
    expect(screen.getByText('ssh')).toBeInTheDocument();
  });

  it('applies the yellow canary styling for canary events', () => {
    render(<ProtocolBadge protocol="canary" />);
    expect(screen.getByText('canary').className).toContain('yellow');
  });

  it('matches colors case-insensitively', () => {
    render(<ProtocolBadge protocol="CANARY" />);
    expect(screen.getByText('CANARY').className).toContain('yellow');
  });

  it('falls back to gray for an unknown protocol', () => {
    render(<ProtocolBadge protocol="gopher" />);
    expect(screen.getByText('gopher').className).toContain('gray');
  });

  it('gives known network protocols their own (non-gray) color', () => {
    render(<ProtocolBadge protocol="ssh" />);
    expect(screen.getByText('ssh').className).not.toContain('gray');
  });
});
