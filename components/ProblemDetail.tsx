import { useMemo, useState, useEffect, type CSSProperties } from 'react';
import { CTFProblem, ProblemFile } from '../App';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Input } from './ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { ScrollArea } from './ui/scroll-area';
import { Sparkles, Download, AlertCircle, CheckCircle2, Copy, Wrench } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from './ui/dropdown-menu';
import ReactMarkdown, { Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog';

interface ProblemDetailProps {
  problem: CTFProblem | null;
  competitionId?: string | null;
  onAiSolveRequest?: (problem: CTFProblem, command: string) => void;
  onAiWriteupRequest?: (problem: CTFProblem) => void;
  onStartSession?: (problem: CTFProblem) => void;
  onStopSession?: (problemId: string) => void;
  isSessionActive?: boolean;
  onFlagSave?: (problemId: string, flagValue: string) => Promise<void> | void;
  writeupStatus?: {
    status: 'idle' | 'recording' | 'saving' | 'success' | 'error';
    message?: string;
  };
}

type ConnectionDetail = {
  raw: string;
  type: 'nc' | 'url' | 'other';
  url?: string;
};

const WRITEUP_CONTENT_STYLE: CSSProperties = { overflowWrap: 'anywhere' };

const stripBullets = (value: string) => value.replace(/^[-*>•\s]+/, '').trim();

const isConnectionLine = (value: string) => {
  const cleaned = stripBullets(value);
  if (!cleaned) return false;
  return /^nc\s+/i.test(cleaned) || /^https?:\/\/\S+/i.test(cleaned);
};

const classifyConnection = (value: string): ConnectionDetail => {
  const cleaned = stripBullets(value);
  const urlMatch = cleaned.match(/https?:\/\/\S+/i);
  if (urlMatch) {
    return { raw: cleaned, type: 'url', url: urlMatch[0] };
  }
  if (/^nc\s+/i.test(cleaned)) {
    return { raw: cleaned, type: 'nc' };
  }
  return { raw: cleaned, type: 'other' };
};

const extractConnectionInfo = (description: string) => {
  const lines = description?.split(/\r?\n/) ?? [];
  const sanitizedLines = [...lines];
  const connectionInfo: ConnectionDetail[] = [];
  let awaitingConnection = false;

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed && !awaitingConnection) return;

    const inlineMatch = trimmed.match(/^\[?\s*접속\s*정보\s*\]?:?\s*(.*)$/i);
    if (inlineMatch) {
      const rest = inlineMatch[1].trim();
      sanitizedLines[index] = '';
      if (rest) {
        if (isConnectionLine(rest)) {
          connectionInfo.push(classifyConnection(rest));
          awaitingConnection = false;
        } else {
          awaitingConnection = true;
        }
      } else {
        awaitingConnection = true;
      }
      return;
    }

    if (awaitingConnection) {
      awaitingConnection = false;
      if (isConnectionLine(trimmed)) {
        connectionInfo.push(classifyConnection(trimmed));
        sanitizedLines[index] = '';
        return;
      }
    }

    if (isConnectionLine(trimmed)) {
      connectionInfo.push(classifyConnection(trimmed));
      sanitizedLines[index] = '';
    }
  });

  const sanitizedDescription = sanitizedLines
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  return { sanitizedDescription, connectionInfo };
};

const resolveFileHref = (file: ProblemFile | undefined | null) => {
  if (!file) return null;
  const normalize = (value?: string) => (typeof value === 'string' && value.trim() ? value.trim() : null);
  const url = normalize(file.url);
  const downloadUrl = normalize(file.downloadUrl);

  const isHttp = (value: string | null) => Boolean(value && /^https?:\/\//i.test(value));
  const isAbsolutePath = (value: string | null) => Boolean(value && value.startsWith('/'));

  if (isAbsolutePath(url) || isHttp(url)) return url;
  if (isAbsolutePath(downloadUrl) || isHttp(downloadUrl)) return downloadUrl;
  return downloadUrl ?? url;
};

const convertPublicFilesPathToLocal = (href: string | null) => {
  if (!href) return null;
  const FILES_PREFIX = '/files/';
  if (href.startsWith(FILES_PREFIX)) {
    return `storage/ctf-files/${href.slice(FILES_PREFIX.length)}`;
  }
  try {
    const parsed = new URL(href, 'http://local');
    if (parsed.pathname.startsWith(FILES_PREFIX)) {
      return `storage/ctf-files/${parsed.pathname.slice(FILES_PREFIX.length)}`;
    }
  } catch {
    // ignore invalid URLs; fall through to returning the original href
  }
  return href;
};

const normalizeAssetKey = (value?: string | null) => {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const withoutQuery = trimmed.split(/[?#]/)[0];
  return withoutQuery
    .replace(/\\/g, '/')
    .replace(/^(\.\/)+/, '')
    .replace(/^\/+/, '')
    .replace(/\/\/+/g, '/')
    .toLowerCase();
};

const createAssetUrlResolver = (files?: ProblemFile[] | null) => {
  if (!files || files.length === 0) {
    return (input?: string | null) => (input ? input.trim() || null : null);
  }

  const referenceMap = new Map<string, string>();
  const register = (key?: string | null, url?: string | null) => {
    if (!key || !url) return;
    const normalized = normalizeAssetKey(key);
    if (!normalized) return;
    if (!referenceMap.has(normalized)) {
      referenceMap.set(normalized, url);
    }
    const base = normalized.split('/').pop();
    if (base && !referenceMap.has(base)) {
      referenceMap.set(base, url);
    }
  };

  files.forEach((file) => {
    const href = resolveFileHref(file);
    register(file?.name, href);
    register(file?.url, href);
    register(file?.downloadUrl, href);
  });

  return (input?: string | null) => {
    if (!input) return null;
    const trimmed = input.trim();
    if (!trimmed) return null;
    if (/^(?:[a-z][a-z\d+\-.]*:|data:|mailto:|tel:)/i.test(trimmed) || trimmed.startsWith('//')) {
      return trimmed;
    }
    const normalized = normalizeAssetKey(trimmed);
    if (normalized) {
      if (referenceMap.has(normalized)) {
        return referenceMap.get(normalized)!;
      }
      const basename = normalized.split('/').pop();
      if (basename && referenceMap.has(basename)) {
        return referenceMap.get(basename)!;
      }
    }
    return trimmed;
  };
};

export function ProblemDetail({
  problem,
  competitionId,
  onAiSolveRequest,
  onAiWriteupRequest,
  onStartSession,
  onStopSession,
  isSessionActive = false,
  onFlagSave,
  writeupStatus,
}: ProblemDetailProps) {
  const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '/api').replace(/\/$/, '');
  const resolveAssetUrl = useMemo(() => createAssetUrlResolver(problem?.files ?? null), [problem?.files]);
  const [isIdaFileDialogOpen, setIsIdaFileDialogOpen] = useState(false);
  const [selectedIdaFile, setSelectedIdaFile] = useState<string | null>(null);
  const idaFileOptions = useMemo(() => {
    if (!problem?.files) return [];
    return problem.files
      .map((file) => {
        const href = resolveFileHref(file);
        if (!href) return null;
        return {
          name: file.name,
          href,
          localPath: convertPublicFilesPathToLocal(href),
        };
      })
      .filter((item): item is { name: string; href: string; localPath: string | null } => Boolean(item));
  }, [problem?.files]);
  const markdownComponents = useMemo<Components>(() => ({
    a: ({ ...props }) => {
      const resolvedHref = resolveAssetUrl(props.href) ?? props.href ?? undefined;
      return (
        <a
          {...props}
          href={resolvedHref}
          className="text-blue-600 hover:text-blue-700 underline break-words"
          target="_blank"
          rel="noopener noreferrer"
        />
      );
    },
    img: ({ ...props }) => {
      const { className, alt, src, ...rest } = props;
      const resolvedSrc = resolveAssetUrl(src);
      if (!resolvedSrc) {
        return (
          <span className="inline-flex items-center rounded border border-dashed border-slate-300 bg-slate-50 px-2 py-1 text-xs text-slate-500">
            {alt ?? '이미지를 불러오지 못했습니다.'}
          </span>
        );
      }
      const composedClassName = ['max-w-full rounded-md border border-slate-200 bg-white', className]
        .filter(Boolean)
        .join(' ');
      return (
        <img
          {...rest}
          src={resolvedSrc}
          alt={alt ?? ''}
          className={composedClassName}
          loading="lazy"
        />
      );
    },
  }), [resolveAssetUrl]);
  const { sanitizedDescription, connectionInfo } = useMemo(() => {
    if (!problem?.description) {
      return { sanitizedDescription: '', connectionInfo: [] };
    }
    const parsed = extractConnectionInfo(problem.description);
    return {
      sanitizedDescription: parsed.sanitizedDescription ?? problem.description,
      connectionInfo: parsed.connectionInfo ?? [],
    };
  }, [problem?.description]);

  const buildDefaultGuidanceLines = (normalizedCategory: CTFProblem['normalizedCategory']) => {
    const lines: string[] = [
      '1. CTF 대회 문제를 풀이해줘. 서버가 있다면 서버에서 정보를 얻어 플래그를 얻을 때 까지 대답하지말고 계속 분석해줘.',
      '2. 만약 카테고리가 리버싱/포너블 문제라면 IDA MCP가 연결되어 있으니 그걸 사용해서 분석해줘.',
      '3. 코드 작성 및 실행이 필요하다면 poc 디렉터리 밑에서 진행해줘.',
      '4. 만약 플래그를 얻었다면 플래그를 반환해줘.',
    ];
    if (normalizedCategory === 'Forensics') {
      lines.push('5. Volatility mcp도 있으니 만약 필요하다면 사용해도 좋아');
    }
    return lines;
  };

  const getEnvPromptForCategory = (normalizedCategory: CTFProblem['normalizedCategory']) => {
    const env = import.meta.env as any;
    const byCategory: Partial<Record<CTFProblem['normalizedCategory'], string | undefined>> = {
      Web: env.VITE_PROMPT_WEB,
      Pwnable: env.VITE_PROMPT_PWNABLE ?? env.VITE_PROMPT_PWN,
      Crypto: env.VITE_PROMPT_CRYPTO,
      Forensics: env.VITE_PROMPT_FORENSICS,
      Reversing: env.VITE_PROMPT_REVERSING,
      Misc: env.VITE_PROMPT_MISC,
    };
    const fromCategory = byCategory[normalizedCategory];
    const fromDefault = env.VITE_PROMPT_DEFAULT;
    const value =
      typeof fromCategory === 'string' && fromCategory.trim()
        ? fromCategory
        : typeof fromDefault === 'string' && fromDefault.trim()
          ? fromDefault
          : null;
    return value && value.trim().length > 0 ? value : null;
  };

  const buildCliCommandPayload = () => {
    if (!problem) return '';
    const descriptionText = sanitizedDescription?.trim()
      ? sanitizedDescription.trim()
      : '설명이 제공되지 않았습니다.';
    const connectionLines =
      connectionInfo.length > 0
        ? connectionInfo.map((info) => info.url ?? info.raw).join('\n')
        : '없음';
    const fileSummaries =
      problem.files && problem.files.length > 0
        ? problem.files.map((file, index) => {
            const href = resolveFileHref(file);
            const localPath = convertPublicFilesPathToLocal(href);
            const label = file?.name?.trim() ? file.name.trim() : `파일 ${index + 1}`;
            return localPath ? `${label}: ${localPath}` : label;
          })
        : [];

    const lines = [
      '[문제 정보]',
      `제목: ${problem.title}`,
      `카테고리: ${problem.category}`,
      `난이도: ${problem.difficulty}`,
      `포인트: ${problem.points}`,
      '',
      '[문제 설명]',
      descriptionText,
      '',
      '[접속 정보]',
      connectionLines,
    ];

    if (fileSummaries.length > 0) {
      lines.push('', '[문제 파일]', ...fileSummaries);
    }

    const envPrompt = getEnvPromptForCategory(problem.normalizedCategory);
    if (envPrompt) {
      lines.push('', ...envPrompt.split('\n'));
    } else {
      lines.push('', ...buildDefaultGuidanceLines(problem.normalizedCategory));
    }

    return lines.join('\n');
  };

  const [flagValue, setFlagValue] = useState(() => (problem?.flag ?? ''));
  const [isSavingFlag, setIsSavingFlag] = useState(false);
  const [flagSaveState, setFlagSaveState] = useState<'idle' | 'success' | 'error'>('idle');
  const [flagSaveError, setFlagSaveError] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [copyMessage, setCopyMessage] = useState<string | null>(null);
  const [idaStatus, setIdaStatus] = useState<'idle' | 'working' | 'success' | 'error'>('idle');
  const [idaMessage, setIdaMessage] = useState<string | null>(null);
  const [idaDisconnecting, setIdaDisconnecting] = useState(false);

  useEffect(() => {
    setFlagValue(problem?.flag ?? '');
    setFlagSaveState('idle');
    setFlagSaveError(null);
  }, [problem?.id, problem?.flag]);

  useEffect(() => {
    setCopyStatus('idle');
    setCopyMessage(null);
  }, [problem?.id, problem?.writeup]);

  useEffect(() => {
    if (copyStatus === 'idle') return;
    const timer = setTimeout(() => {
      setCopyStatus('idle');
      setCopyMessage(null);
    }, 2000);
    return () => clearTimeout(timer);
  }, [copyStatus]);

  const handleAISolve = () => {
    if (!problem || !competitionId) {
      return;
    }
    const command = buildCliCommandPayload();
    if (command) {
      onAiSolveRequest?.(problem, command);
    }
  };

  const handleConnectIda = async (fileHref?: string | null) => {
    if (!problem || !competitionId) return;
    setIdaStatus('working');
    setIdaMessage(null);
    try {
      const payload = fileHref ? { fileUrl: fileHref } : {};
      const response = await fetch(
        `${API_BASE}/competitions/${encodeURIComponent(competitionId)}/problems/${encodeURIComponent(problem.id)}/ida-mcp`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(payload),
        }
      );
      const data = await response.json();
      if (!response.ok || !data?.ok) {
        throw new Error(data?.error || '연결에 실패했습니다.');
      }
      setIdaStatus('success');
      setIdaMessage('IDA MCP 연결 요청을 보냈습니다.');
    } catch (error) {
      setIdaStatus('error');
      setIdaMessage(error instanceof Error ? error.message : '연결에 실패했습니다.');
    } finally {
      setTimeout(() => {
        setIdaStatus('idle');
        setIdaMessage(null);
      }, 2500);
    }
  };

  const handleDisconnectIda = async () => {
    if (!problem || !competitionId) return;
    setIdaDisconnecting(true);
    setIdaMessage(null);
    try {
      const response = await fetch(
        `${API_BASE}/competitions/${encodeURIComponent(competitionId)}/problems/${encodeURIComponent(problem.id)}/ida-mcp`,
        {
          method: 'DELETE',
          credentials: 'include',
        }
      );
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data?.ok === false) {
        throw new Error(data?.error || '연결 해제에 실패했습니다.');
      }
      setIdaStatus('idle');
      setIdaMessage('연결을 해제했습니다.');
    } catch (error) {
      setIdaStatus('error');
      setIdaMessage(error instanceof Error ? error.message : '연결 해제에 실패했습니다.');
    } finally {
      setIdaDisconnecting(false);
      setTimeout(() => setIdaMessage(null), 2500);
    }
  };
  const handleIdaSelectionConfirm = () => {
    if (!selectedIdaFile) return;
    handleConnectIda(selectedIdaFile);
    handleIdaDialogOpenChange(false);
  };
  const handleIdaToolRequest = () => {
    if (!problem) return;
    if (!competitionId || idaFileOptions.length === 0) {
      handleConnectIda();
      return;
    }
    if (idaFileOptions.length === 1) {
      handleConnectIda(idaFileOptions[0].href);
      return;
    }
    setSelectedIdaFile((prev) => prev ?? idaFileOptions[0]?.href ?? null);
    setIsIdaFileDialogOpen(true);
  };
  const handleIdaDialogOpenChange = (open: boolean) => {
    setIsIdaFileDialogOpen(open);
    if (!open) {
      setSelectedIdaFile(null);
    }
  };

  const handleFlagSubmit = async () => {
    if (!problem || !onFlagSave) return;
    setIsSavingFlag(true);
    setFlagSaveState('idle');
    setFlagSaveError(null);
    try {
      await onFlagSave(problem.id, flagValue);
      setFlagSaveState('success');
    } catch (error) {
      setFlagSaveState('error');
      setFlagSaveError(error instanceof Error ? error.message : '플래그를 저장하지 못했습니다.');
    } finally {
      setIsSavingFlag(false);
    }
  };

  const writeupState = writeupStatus?.status ?? 'idle';
  const isWriteupBusy = writeupState === 'recording' || writeupState === 'saving';
  const writeupStateMessage = (() => {
    switch (writeupState) {
      case 'recording':
        return writeupStatus?.message ?? '세션 응답을 수집하는 중입니다...';
      case 'saving':
        return writeupStatus?.message ?? 'AI 풀이를 저장하는 중입니다...';
      case 'success':
        return writeupStatus?.message ?? 'AI 풀이를 저장했습니다.';
      case 'error':
        return writeupStatus?.message ?? 'AI 풀이를 저장하지 못했습니다.';
      default:
        return null;
    }
  })();
  const writeupContent = problem?.writeup?.trim();
  const writeupUpdatedLabel = problem?.writeupUpdatedAt
    ? new Date(problem.writeupUpdatedAt).toLocaleString('ko-KR')
    : null;

  const handleCopyWriteup = async () => {
    if (!writeupContent) return;
    const text = writeupContent;
    const fallbackCopy = () => {
      if (typeof document === 'undefined') return false;
      try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', 'true');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        const succeeded = document.execCommand('copy');
        document.body.removeChild(textarea);
        return succeeded;
      } catch {
        return false;
      }
    };

    try {
      let copied = false;
      if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        copied = true;
      } else {
        copied = fallbackCopy();
      }

      if (!copied) {
        throw new Error('Clipboard unavailable');
      }

      setCopyStatus('success');
      setCopyMessage('클립보드에 복사했습니다.');
    } catch (error) {
      console.error('Failed to copy writeup', error);
      setCopyStatus('error');
      setCopyMessage('복사하지 못했습니다.');
    }
  };

  if (!problem) {
    return (
      <Card className="bg-white border-slate-200 p-6 h-full flex items-center justify-center">
        <div className="text-center text-slate-500">
          <AlertCircle className="size-12 mx-auto mb-3 opacity-50" />
          <p>문제를 선택하세요</p>
        </div>
      </Card>
    );
  }

  return (
    <>
      <Card className="bg-white border-slate-200 p-6">
      <div className="space-y-6">
        {/* Header */}
        <div className="space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2">
                {problem.solved && (
                  <CheckCircle2 className="size-5 text-green-600" />
                )}
                <h2 className="text-slate-900">{problem.title}</h2>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Badge className="bg-blue-50 text-blue-700 border-blue-200">
                  {problem.category}
                </Badge>
                <Badge className="bg-amber-50 text-amber-700 border-amber-200">
                  {problem.difficulty}
                </Badge>
                <Badge variant="outline" className="text-slate-600 border-slate-300">
                  {problem.source}
                </Badge>
              </div>
            </div>
            <div className="text-right shrink-0">
              <div className="text-amber-600">{problem.points}</div>
              <div className="text-slate-500 text-sm">Points</div>
            </div>
          </div>

          {/* AI Solve Button */}
          <Button
            onClick={handleAISolve}
            disabled={!competitionId}
            className="w-full bg-slate-900 hover:bg-slate-800 disabled:bg-slate-300 disabled:text-slate-600"
          >
            <>
              <Sparkles className="size-4 mr-2" />
              AI로 문제 분석하기
            </>
          </Button>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={!competitionId || isSessionActive}
              onClick={() => problem && onStartSession?.(problem)}
              className="border-slate-300 text-slate-700"
            >
              Codex 세션 시작
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!problem || !isSessionActive}
              onClick={() => problem && onStopSession?.(problem.id)}
              className="border-red-200 text-red-600 hover:text-red-700 hover:bg-red-50 disabled:text-slate-400"
            >
              세션 종료
            </Button>
          </div>
          {!competitionId && (
            <p className="text-xs text-red-500">
              대회 정보를 불러온 뒤 AI 분석을 실행할 수 있습니다.
            </p>
          )}
          <div className="flex justify-end">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button type="button" variant="outline" className="border-slate-300 text-slate-700">
                  <Wrench className="size-4 mr-2" />
                  도구
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onSelect={() => problem && onAiWriteupRequest?.(problem)}
                  disabled={!problem || !competitionId || !isSessionActive || isWriteupBusy}
                >
                  {isWriteupBusy ? 'AI 풀이 저장 중...' : 'AI 풀이 저장'}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onSelect={handleIdaToolRequest}
                  disabled={!competitionId}
                >
                  IDA MCP 연결
                </DropdownMenuItem>
                <DropdownMenuItem
                  onSelect={handleDisconnectIda}
                  disabled={!competitionId || idaDisconnecting}
                >
                  연결 해제
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
          <div className="flex flex-col gap-1">
            {writeupStateMessage && (
              <span
                className={`text-xs ${
                  writeupState === 'error'
                    ? 'text-red-500'
                    : writeupState === 'success'
                      ? 'text-green-600'
                      : 'text-amber-700'
                }`}
              >
                {writeupStateMessage}
              </span>
            )}
            {idaMessage && (
              <span className={`text-xs ${idaStatus === 'error' ? 'text-red-500' : 'text-amber-700'}`}>{idaMessage}</span>
            )}
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-slate-900">플래그</p>
              {flagSaveState === 'success' && (
                <span className="text-xs text-green-600">저장되었습니다.</span>
              )}
            </div>
            <div className="flex flex-col sm:flex-row gap-2">
              <Input
                value={flagValue}
                onChange={(event) => {
                  setFlagValue(event.target.value);
                  if (flagSaveState !== 'idle') {
                    setFlagSaveState('idle');
                    setFlagSaveError(null);
                  }
                }}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    handleFlagSubmit();
                  }
                }}
                disabled={!competitionId || isSavingFlag || !onFlagSave}
                placeholder="예: FLAG{example}"
                className="bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400"
              />
              <Button
                type="button"
                onClick={handleFlagSubmit}
                disabled={!competitionId || isSavingFlag || !onFlagSave}
                className="sm:w-auto w-full"
              >
                {isSavingFlag ? '저장 중...' : '플래그 저장'}
              </Button>
            </div>
            {flagSaveState === 'error' && flagSaveError && (
              <p className="text-xs text-red-500">{flagSaveError}</p>
            )}
          </div>
        </div>

        {/* Content */}
        <Tabs defaultValue="description" className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <TabsList className="bg-slate-50 border border-slate-200">
              <TabsTrigger
                value="description"
                className="data-[state=active]:bg-slate-900 data-[state=active]:text-white transition-all duration-200 active:scale-95"
              >
                설명
              </TabsTrigger>
              <TabsTrigger
                value="files"
                className="data-[state=active]:bg-slate-900 data-[state=active]:text-white transition-all duration-200 active:scale-95"
              >
                파일
              </TabsTrigger>
              <TabsTrigger
                value="writeup"
                className="data-[state=active]:bg-slate-900 data-[state=active]:text-white transition-all duration-200 active:scale-95"
              >
                AI 풀이
              </TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="description">
            <ScrollArea className="h-[500px]">
              <div className="space-y-4 pr-4">
                <div>
                  <h3 className="text-slate-900 mb-2">문제 설명</h3>
                  <ReactMarkdown
                    className="prose prose-slate max-w-none text-slate-700 break-words prose-pre:whitespace-pre-wrap"
                    remarkPlugins={[remarkGfm]}
                    components={markdownComponents}
                  >
                    {sanitizedDescription}
                  </ReactMarkdown>
                </div>

                <div className="pt-4 border-t border-slate-200">
                  <h3 className="text-slate-900 mb-2">접속 정보</h3>
                  {connectionInfo.length > 0 ? (
                    <div className="space-y-2">
                      {connectionInfo.map((info, index) => (
                        <div
                          key={`${info.raw}-${index}`}
                          className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-800 break-words"
                        >
                          {info.type === 'url' && info.url ? (
                            <a
                              href={info.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-600 hover:text-blue-700 underline break-words"
                            >
                              {info.url}
                            </a>
                          ) : (
                            <code className="bg-transparent p-0 text-slate-800">
                              {info.raw}
                            </code>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-500 text-sm border border-dashed border-slate-200 rounded-lg p-3">
                      서버가 없습니다.
                    </p>
                  )}
                </div>

                <div className="pt-4 border-t border-slate-200">
                  <p className="text-slate-600 text-sm">
                    출처: {problem.source}
                  </p>
                  <p className="text-slate-500 text-sm">
                    크롤링 시간: {new Date(problem.createdAt).toLocaleString('ko-KR')}
                  </p>
                </div>
              </div>
            </ScrollArea>
          </TabsContent>

          <TabsContent value="files">
            <ScrollArea className="h-[500px]">
              <div className="space-y-2 pr-4">
                {problem.files && problem.files.length > 0 ? (
                  problem.files.map((file, index) => {
                    const fileHref = resolveFileHref(file);
                    const localPath = fileHref ? convertPublicFilesPathToLocal(fileHref) : null;
                    return (
                      <Card
                        key={index}
                        className="p-4 bg-slate-50 border-slate-200 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
                      >
                        <div className="flex flex-col gap-1 pr-4">
                          <span className="text-slate-700 break-all">{file.name}</span>
                          {localPath && (
                            <span className="text-xs text-slate-500 break-all">
                              {localPath}
                            </span>
                          )}
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          {fileHref ? (
                            <Button
                              size="sm"
                              variant="outline"
                              asChild
                              className="border-slate-300 text-slate-700"
                            >
                              <a href={fileHref} download target="_blank" rel="noreferrer">
                                <Download className="size-4 mr-2" />
                                다운로드
                              </a>
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              variant="outline"
                              disabled
                              className="border-slate-300 text-slate-400"
                            >
                              <Download className="size-4 mr-2" />
                              링크 없음
                            </Button>
                          )}
                        </div>
                      </Card>
                    );
                  })
                ) : (
                  <p className="text-slate-500 text-center py-8">
                    첨부된 파일이 없습니다
                  </p>
                )}
              </div>
            </ScrollArea>
          </TabsContent>
          <TabsContent value="writeup">
            <div className="space-y-3">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h3 className="text-slate-900">AI 풀이</h3>
                  <p className="text-slate-500 text-sm">
                    {writeupUpdatedLabel ? `저장됨: ${writeupUpdatedLabel}` : '아직 저장된 AI 풀이가 없습니다.'}
                  </p>
                  {writeupStateMessage && (
                    <span
                      className={`text-xs ${
                        writeupState === 'error'
                          ? 'text-red-500'
                          : writeupState === 'success'
                            ? 'text-green-600'
                            : 'text-amber-600'
                      }`}
                    >
                      {writeupStateMessage}
                    </span>
                  )}
                </div>
                <div className="flex flex-col gap-1 items-start sm:items-end">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="border-slate-300 text-slate-700"
                    onClick={handleCopyWriteup}
                    disabled={!writeupContent}
                  >
                    <Copy className="size-3.5 mr-1" />
                    AI 풀이 복사
                  </Button>
                  {copyMessage && (
                    <span
                      className={`text-xs ${
                        copyStatus === 'error' ? 'text-red-500' : 'text-green-600'
                      }`}
                    >
                      {copyMessage}
                    </span>
                  )}
                </div>
              </div>
              <ScrollArea className="h-[500px]">
                <div className="border border-slate-200 rounded-lg bg-white p-4 min-h-[320px]">
                  {writeupContent ? (
                    <pre
                      className="whitespace-pre-wrap break-words text-slate-700 w-full"
                      style={WRITEUP_CONTENT_STYLE}
                    >
                      {writeupContent}
                    </pre>
                  ) : (
                    <p className="text-slate-500 text-sm text-center py-12">
                      세션에서 생성된 AI 풀이가 저장되면 이곳에 표시됩니다.
                    </p>
                  )}
                </div>
              </ScrollArea>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </Card>
      <Dialog open={isIdaFileDialogOpen} onOpenChange={handleIdaDialogOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>IDA MCP 연결</DialogTitle>
            <DialogDescription>
              연결할 파일을 선택하세요.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {idaFileOptions.length === 0 ? (
              <p className="text-sm text-slate-500">
                선택 가능한 파일이 없습니다.
              </p>
            ) : (
              idaFileOptions.map((file) => (
                <label
                  key={file.href}
                  className={`flex items-start gap-3 rounded-lg border p-3 text-sm ${
                    selectedIdaFile === file.href ? 'border-slate-900 bg-slate-900/5' : 'border-slate-200 bg-slate-50'
                  }`}
                >
                  <input
                    type="radio"
                    name="ida-file"
                    value={file.href}
                    checked={selectedIdaFile === file.href}
                    onChange={() => setSelectedIdaFile(file.href)}
                    className="mt-1"
                  />
                  <span className="flex flex-col gap-1">
                    <span className="text-slate-800 break-all">{file.name}</span>
                    {file.localPath && (
                      <span className="text-xs text-slate-500 break-all">{file.localPath}</span>
                    )}
                  </span>
                </label>
              ))
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => handleIdaDialogOpenChange(false)}>
              취소
            </Button>
            <Button onClick={handleIdaSelectionConfirm} disabled={!selectedIdaFile}>
              연결
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
