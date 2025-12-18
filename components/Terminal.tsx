import { useState, useRef, useEffect, useCallback } from 'react';
import { Terminal as TerminalIcon, PlugZap, Trash2 } from 'lucide-react';
import { Terminal as XtermTerminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { Card } from './ui/card';
import { Button } from './ui/button';

interface TerminalCommandRequest {
  id: number;
  command: string;
  appendNewline?: boolean;
  autoSubmit?: boolean;
  echo?: boolean;
}

interface TerminalProps {
  commandRequest?: TerminalCommandRequest | null;
  onCommandHandled?: (handledId: number) => void;
  sessionName?: string;
  onOutput?: (chunk: string) => void;
  sessionId?: string | null;
  onSessionReady?: (sessionId: string) => void;
  onSessionExit?: () => void;
}

type ConnectionStatus = 'connecting' | 'ready' | 'error' | 'closed';

const CLI_WS_PATH = import.meta.env.VITE_CLI_WS_PATH ?? '/ws/codex';
const AUTO_SUBMIT_ENTER_DELAY_MS = Number(import.meta.env.VITE_CLI_AUTO_SUBMIT_DELAY_MS ?? 1000);

const buildWsUrl = (sessionId?: string | null) => {
  if (typeof window === 'undefined') {
    return '';
  }
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const base = `${protocol}://${window.location.host}${CLI_WS_PATH}`;
  if (sessionId && sessionId.trim()) {
    const sep = base.includes('?') ? '&' : '?';
    return `${base}${sep}sid=${encodeURIComponent(sessionId.trim())}`;
  }
  return base;
};

export function Terminal({ commandRequest = null, onCommandHandled, sessionName = 'Codex 인터랙티브 CLI', onOutput, sessionId = null, onSessionReady, onSessionExit }: TerminalProps) {
  const [status, setStatus] = useState<ConnectionStatus>('connecting');
  const socketRef = useRef<WebSocket | null>(null);
  const pendingExternalRef = useRef<TerminalCommandRequest | null>(null);
  const termRef = useRef<XtermTerminal | null>(null);
  const terminalContainerRef = useRef<HTMLDivElement>(null);
  const terminalBufferRef = useRef<string[]>([]);
  const initialBannerRef = useRef(false);
  const sessionReadyRef = useRef(false);
  const onCommandHandledRef = useRef<TerminalProps['onCommandHandled']>(onCommandHandled);
  const onOutputRef = useRef<TerminalProps['onOutput']>(onOutput);
  const onSessionReadyRef = useRef<TerminalProps['onSessionReady']>(onSessionReady);
  const onSessionExitRef = useRef<TerminalProps['onSessionExit']>(onSessionExit);

  useEffect(() => {
    onCommandHandledRef.current = onCommandHandled;
  }, [onCommandHandled]);

  useEffect(() => {
    onOutputRef.current = onOutput;
  }, [onOutput]);
  useEffect(() => {
    onSessionReadyRef.current = onSessionReady;
  }, [onSessionReady]);
  useEffect(() => {
    onSessionExitRef.current = onSessionExit;
  }, [onSessionExit]);

  const writeToTerminal = useCallback((chunk: string) => {
    if (!chunk) return;
    const terminal = termRef.current;
    if (!terminal) {
      terminalBufferRef.current.push(chunk);
      return;
    }
    if (terminalBufferRef.current.length > 0) {
      terminalBufferRef.current.forEach((pending) => terminal.write(pending));
      terminalBufferRef.current = [];
    }
    terminal.write(chunk);
  }, []);

  const writeBanner = useCallback(() => {
    writeToTerminal('=== Codex 인터랙티브 터미널 ===\r\n');
    writeToTerminal('브라우저에서 Codex 세션과 직접 대화하세요.\r\n');
  }, [writeToTerminal]);

  const writeSystemMessage = useCallback((message: string) => {
    writeToTerminal(`\r\n[system] ${message}\r\n`);
  }, [writeToTerminal]);

  const writeErrorMessage = useCallback((message: string) => {
    writeToTerminal(`\r\n[error] ${message}\r\n`);
  }, [writeToTerminal]);

  const echoCommandLocally = useCallback((command: string) => {
    writeToTerminal(`\r\n$ ${command}\r\n`);
  }, [writeToTerminal]);

  useEffect(() => {
    if (initialBannerRef.current) return;
    initialBannerRef.current = true;
    writeBanner();
  }, [writeBanner]);

  const sendJsonMessage = useCallback((payload: Record<string, unknown>) => {
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    socket.send(JSON.stringify(payload));
    return true;
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;
    const container = terminalContainerRef.current;
    if (!container) return undefined;

    const terminal = new XtermTerminal({
      convertEol: true,
      rows: 30,
      fontSize: 13,
      fontFamily: 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace',
      theme: {
        background: '#0f172a',
        foreground: '#f8fafc',
        cursor: '#f8fafc',
      },
      allowTransparency: false,
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(container);

    const safeFit = () => {
      try {
        fitAddon.fit();
      } catch {
        // ignore
      }
    };

    safeFit();
    termRef.current = terminal;

    if (terminalBufferRef.current.length > 0) {
      terminalBufferRef.current.forEach((pending) => terminal.write(pending));
      terminalBufferRef.current = [];
    }

    const inputDisposable = terminal.onData((data) => {
      const didSend = sendJsonMessage({ type: 'input', data });
      if (!didSend) {
        writeErrorMessage('아직 세션이 준비되지 않았습니다.');
      }
    });

    terminal.focus();
    const focusOnClick = () => terminal.focus();
    container.addEventListener('click', focusOnClick);

    const resizeObserver = typeof ResizeObserver !== 'undefined'
      ? new ResizeObserver(() => safeFit())
      : null;
    resizeObserver?.observe(container);
    window.addEventListener('resize', safeFit);

    return () => {
      inputDisposable.dispose();
      resizeObserver?.disconnect();
      window.removeEventListener('resize', safeFit);
      container.removeEventListener('click', focusOnClick);
      terminal.dispose();
      termRef.current = null;
    };
  }, [sendJsonMessage, writeErrorMessage]);

  const closeSocket = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.onopen = null;
      socketRef.current.onmessage = null;
      socketRef.current.onerror = null;
      socketRef.current.onclose = null;
      socketRef.current.close();
      socketRef.current = null;
    }
  }, []);

  const sendCommandToSocket = useCallback((command: string, options?: { echo?: boolean; appendNewline?: boolean }) => {
    if (!command.trim()) return false;
    const payload: Record<string, unknown> = {
      type: 'command',
      command,
    };
    if (options?.appendNewline === false) {
      payload.appendNewline = false;
    }
    const didSend = sendJsonMessage(payload);
    const shouldEcho = options?.echo !== false;
    if (didSend && shouldEcho) {
      echoCommandLocally(command);
    }
    return didSend;
  }, [echoCommandLocally, sendJsonMessage]);

  const flushPendingExternal = useCallback(() => {
    if (!pendingExternalRef.current) return;
    if (!sessionReadyRef.current) return;
    const pending = pendingExternalRef.current;
    const autoSubmit = Boolean(pending.autoSubmit);
    const appendNewline = autoSubmit ? false : pending.appendNewline !== false;
    const shouldEcho = pending.echo !== false;
    const didSend = sendCommandToSocket(pending.command, {
      echo: shouldEcho,
      appendNewline,
    });
    if (didSend) {
      if (autoSubmit) {
        setTimeout(() => {
          if (!socketRef.current || socketRef.current.readyState !== WebSocket.OPEN) {
            return;
          }
          sendJsonMessage({ type: 'input', data: '\r' });
        }, AUTO_SUBMIT_ENTER_DELAY_MS);
      } else if (!appendNewline) {
        writeSystemMessage('문제 정보를 Codex 프롬프트에 채워 넣었습니다. Enter 키로 실행하거나 내용을 수정하세요.');
        termRef.current?.focus();
      }
      onCommandHandledRef.current?.(pending.id);
      pendingExternalRef.current = null;
    }
  }, [sendCommandToSocket, sendJsonMessage, writeSystemMessage]);

  const connect = useCallback(() => {
    closeSocket();
    sessionReadyRef.current = false;
    const wsUrl = buildWsUrl(sessionId);
    if (!wsUrl) {
      writeErrorMessage('WebSocket URL을 계산할 수 없습니다.');
      setStatus('error');
      return;
    }

    writeSystemMessage('Codex 세션에 연결 중...');
    const socket = new WebSocket(wsUrl);
    socketRef.current = socket;
    setStatus('connecting');

    socket.onopen = () => {
      setStatus('ready');
      writeSystemMessage('Codex 세션과 연결되었습니다. 초기화 중...');
    };

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data as string);
        switch (payload?.type) {
          case 'data': {
            const serialized = typeof payload.data === 'string' ? payload.data : String(payload.data ?? '');
            writeToTerminal(serialized);
            onOutputRef.current?.(serialized);
            break;
          }
          case 'ready':
            sessionReadyRef.current = true;
            writeSystemMessage(payload.message ?? '세션이 준비되었습니다.');
            if (payload?.sessionId && typeof payload.sessionId === 'string') {
              onSessionReadyRef.current?.(payload.sessionId);
            }
            flushPendingExternal();
            break;
          case 'exit':
            writeSystemMessage(`프로세스가 종료되었습니다 (code=${payload.exitCode ?? 'unknown'})`);
            setStatus('closed');
            onSessionExitRef.current?.();
            break;
          case 'error':
            writeErrorMessage(payload.message ?? '알 수 없는 오류');
            break;
          default:
            writeToTerminal(String(event.data ?? ''));
        }
      } catch {
        writeToTerminal(String(event.data ?? ''));
      }
    };

    socket.onerror = (error) => {
      console.error('CLI WebSocket error', error);
      writeErrorMessage('WebSocket 오류가 발생했습니다.');
      sessionReadyRef.current = false;
      setStatus('error');
    };

    socket.onclose = () => {
      sessionReadyRef.current = false;
      writeSystemMessage('Codex 세션 연결이 종료되었습니다.');
      setStatus('closed');
    };
  }, [closeSocket, flushPendingExternal, writeErrorMessage, writeSystemMessage, writeToTerminal, sessionId]);

  useEffect(() => {
    connect();
    return () => closeSocket();
  }, [connect, closeSocket]);

  useEffect(() => {
    if (!commandRequest) return;
    pendingExternalRef.current = commandRequest;
    flushPendingExternal();
  }, [commandRequest, flushPendingExternal]);

  const handleClearLog = useCallback(() => {
    if (termRef.current) {
      termRef.current.clear();
    }
    terminalBufferRef.current = [];
    writeBanner();
  }, [writeBanner]);

  const statusMeta: Record<ConnectionStatus, { text: string; color: string }> = {
    connecting: { text: '연결 중...', color: 'bg-yellow-400' },
    ready: { text: '연결됨', color: 'bg-green-400' },
    error: { text: '오류 발생', color: 'bg-red-500' },
    closed: { text: '연결 종료', color: 'bg-slate-400' },
  };

  const statusIndicator = statusMeta[status];

  return (
    <Card className="bg-white border-slate-200 p-6">
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-slate-900 rounded-lg">
            <TerminalIcon className="size-5 text-white" />
          </div>
          <div>
            <h2 className="text-slate-900">{sessionName}</h2>
            <p className="text-slate-600 text-sm">브라우저에서 codex 세션과 지속적으로 대화하세요.</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
          <span className={`size-2 rounded-full ${statusIndicator.color}`} aria-hidden="true" />
          <span>{statusIndicator.text}</span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={connect}
            className="h-6 text-xs px-2 border-slate-300 text-slate-600"
          >
            <PlugZap className="size-3 mr-1" />
            재연결
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleClearLog}
            className="h-6 text-xs px-2 border-slate-300 text-slate-600"
          >
            <Trash2 className="size-3 mr-1" />
            로그 지우기
          </Button>
        </div>

        <div className="bg-slate-900 rounded-lg border border-slate-300 overflow-hidden">
          <div className="bg-slate-800 px-4 py-2 flex items-center gap-2 border-b border-slate-700">
            <div className="flex gap-2">
              <div className="size-3 rounded-full bg-red-500" />
              <div className="size-3 rounded-full bg-yellow-500" />
              <div className="size-3 rounded-full bg-green-500" />
            </div>
            <span className="text-slate-400 text-sm ml-2">codex@ctf-hunter</span>
          </div>
          <div className="p-0 border-t border-slate-700">
            <div ref={terminalContainerRef} className="h-[500px] w-full bg-slate-900" />
          </div>
        </div>
      </div>
    </Card>
  );
}
