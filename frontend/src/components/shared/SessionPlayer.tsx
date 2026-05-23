'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Play, Pause, SkipForward, RotateCcw } from 'lucide-react';
import clsx from 'clsx';
import { formatDate } from '@/utils/formatters';

interface Command {
  timestamp: string;
  command: string;
  output?: string;
}

interface SessionPlayerProps {
  commands: Command[] | null;
  keystrokes?: string[] | null;
  className?: string;
}

export default function SessionPlayer({
  commands,
  keystrokes,
  className,
}: SessionPlayerProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(-1);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const terminalRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  const commandList = commands || [];

  const scrollToBottom = useCallback(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [currentIndex, scrollToBottom]);

  useEffect(() => {
    if (!isPlaying || currentIndex >= commandList.length - 1) {
      if (currentIndex >= commandList.length - 1) {
        setIsPlaying(false);
      }
      return;
    }

    const delay = 1000 / playbackSpeed;

    timerRef.current = setTimeout(() => {
      setCurrentIndex((prev) => prev + 1);
    }, delay);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [isPlaying, currentIndex, commandList.length, playbackSpeed]);

  const handlePlay = () => {
    if (currentIndex >= commandList.length - 1) {
      setCurrentIndex(-1);
    }
    setIsPlaying(true);
    if (currentIndex === -1) {
      setCurrentIndex(0);
    }
  };

  const handlePause = () => {
    setIsPlaying(false);
  };

  const handleSkip = () => {
    setCurrentIndex(commandList.length - 1);
    setIsPlaying(false);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentIndex(-1);
  };

  const visibleCommands = commandList.slice(0, currentIndex + 1);

  return (
    <div className={clsx('flex flex-col gap-3', className)}>
      {/* Controls */}
      <div className="flex items-center gap-2">
        {isPlaying ? (
          <button
            onClick={handlePause}
            className="btn-secondary flex items-center gap-2 text-sm"
          >
            <Pause className="w-4 h-4" />
            Pause
          </button>
        ) : (
          <button
            onClick={handlePlay}
            className="btn-primary flex items-center gap-2 text-sm"
            disabled={commandList.length === 0}
          >
            <Play className="w-4 h-4" />
            {currentIndex >= commandList.length - 1 ? 'Replay' : 'Play'}
          </button>
        )}

        <button
          onClick={handleSkip}
          className="btn-secondary flex items-center gap-2 text-sm"
          disabled={commandList.length === 0}
        >
          <SkipForward className="w-4 h-4" />
          Skip
        </button>

        <button
          onClick={handleReset}
          className="btn-secondary flex items-center gap-2 text-sm"
        >
          <RotateCcw className="w-4 h-4" />
          Reset
        </button>

        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-gray-500">Speed:</span>
          {[0.5, 1, 2, 4].map((speed) => (
            <button
              key={speed}
              onClick={() => setPlaybackSpeed(speed)}
              className={clsx(
                'px-2 py-1 rounded text-xs font-mono transition-colors',
                playbackSpeed === speed
                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  : 'text-gray-500 hover:text-gray-300'
              )}
            >
              {speed}x
            </button>
          ))}
        </div>

        <div className="text-xs text-gray-500 font-mono">
          {currentIndex + 1}/{commandList.length}
        </div>
      </div>

      {/* Terminal */}
      <div
        ref={terminalRef}
        className="terminal min-h-[300px] max-h-[500px] overflow-auto"
      >
        {commandList.length === 0 ? (
          <div className="text-gray-600 italic">No commands recorded</div>
        ) : currentIndex === -1 ? (
          <div className="text-gray-600 italic">
            Press Play to start session replay...
          </div>
        ) : (
          visibleCommands.map((cmd, idx) => (
            <div key={idx} className="mb-3">
              <div className="flex items-center gap-2 text-gray-500 text-xs mb-1">
                <span>{formatDate(cmd.timestamp, 'HH:mm:ss.SSS')}</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-green-500 font-bold select-none">$</span>
                <span className="text-amber-400">{cmd.command}</span>
              </div>
              {cmd.output && (
                <pre className="text-gray-400 text-xs mt-1 ml-4 whitespace-pre-wrap">
                  {cmd.output}
                </pre>
              )}
            </div>
          ))
        )}

        {isPlaying && (
          <div className="flex items-center gap-1 text-green-500 mt-2">
            <span className="font-bold">$</span>
            <span className="w-2 h-4 bg-green-500 animate-pulse" />
          </div>
        )}
      </div>

      {/* Keystrokes */}
      {keystrokes && keystrokes.length > 0 && (
        <div className="card p-4">
          <h4 className="text-sm font-medium text-gray-400 mb-2">
            Raw Keystrokes
          </h4>
          <div className="font-mono text-xs text-gray-500 break-all bg-[#0a0a0f] rounded p-3">
            {keystrokes.join('')}
          </div>
        </div>
      )}
    </div>
  );
}
