import { useState, useEffect, useCallback, useRef } from 'react';
import { GoogleLogin, type CredentialResponse } from '@react-oauth/google';
import { CTFProblemList } from './components/CTFProblemList';
import { ProblemDetail } from './components/ProblemDetail';
import { Terminal } from './components/Terminal';
import { AdminPanel } from './components/AdminPanel';
import { CompetitionSelector } from './components/CompetitionSelector';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Button } from './components/ui/button';
import { Alert, AlertDescription } from './components/ui/alert';
import { Flag, Terminal as TerminalIcon, List, Settings, Loader2, Power, ArrowUpRight, LogOut } from 'lucide-react';

export interface ProblemFile {
  name: string;
  url: string;
  downloadUrl?: string;
}

export interface CTFProblem {
  id: string;
  title: string;
  category: string;
  normalizedCategory: 'Web' | 'Pwnable' | 'Crypto' | 'Forensics' | 'Reversing' | 'Misc';
  difficulty: 'Easy' | 'Medium' | 'Hard';
  points: number;
  description: string;
  hints: string[];
  files?: ProblemFile[];
  solved: boolean;
  source: string;
  flag?: string | null;
  writeup?: string | null;
  writeupUpdatedAt?: string | null;
  createdAt: string;
}

export interface Competition {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  problemCount: number;
   isShared?: boolean;
}

interface AuthUser {
  email: string;
  name?: string | null;
  picture?: string | null;
}

interface DashboardAppProps {
  user: AuthUser;
  onLogout: () => Promise<void> | void;
}

export default function App() {
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const [isCheckingSession, setIsCheckingSession] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;
  const isSsoConfigured = Boolean(googleClientId);

  const refreshSession = useCallback(async () => {
    setIsCheckingSession(true);
    setAuthError(null);
    try {
      const response = await fetch(`${API_BASE}/auth/me`, {
        credentials: 'include',
      });
      if (!response.ok) {
        setAuthUser(null);
        if (response.status >= 500) {
          setAuthError('세션을 확인하지 못했습니다. 잠시 후 다시 시도해주세요.');
        }
        return;
      }
      const data = await response.json();
      setAuthUser(data.user ?? null);
      setAuthError(null);
    } catch (error) {
      setAuthUser(null);
      setAuthError(error instanceof Error ? error.message : '세션을 확인하지 못했습니다.');
    } finally {
      setIsCheckingSession(false);
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  const handleGoogleSuccess = useCallback(async (credentialResponse: CredentialResponse) => {
    if (!credentialResponse.credential) {
      setAuthError('Google 토큰을 받지 못했습니다.');
      return;
    }
    setIsAuthenticating(true);
    setAuthError(null);
    try {
      const response = await fetch(`${API_BASE}/auth/google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ credential: credentialResponse.credential }),
      });
      const data = await response.json();
      if (!response.ok || data.ok === false) {
        throw new Error(data.error ?? 'Google 인증에 실패했습니다.');
      }
      setAuthUser(data.user);
    } catch (error) {
      setAuthUser(null);
      setAuthError(error instanceof Error ? error.message : 'Google 인증에 실패했습니다.');
    } finally {
      setIsAuthenticating(false);
      setIsCheckingSession(false);
    }
  }, []);

  const handleGoogleError = useCallback(() => {
    setAuthError('Google 로그인에 실패했습니다. 다시 시도해주세요.');
  }, []);

  const handleLogout = useCallback(async () => {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch {
      // ignore logout errors
    } finally {
      setAuthUser(null);
      setAuthError(null);
    }
  }, []);

  if (isCheckingSession) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 text-slate-700">
          <Loader2 className="size-6 animate-spin" />
          <p className="text-sm">세션을 확인하는 중입니다...</p>
        </div>
      </div>
    );
  }

  if (!authUser) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center px-4">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl shadow-sm p-8 space-y-6">
          <div className="space-y-2 text-center">
            <h1 className="text-xl font-semibold text-slate-900">접속 보호</h1>
            <p className="text-sm text-slate-600">허용된 Google 계정만 메인 페이지를 사용할 수 있습니다.</p>
          </div>
          {authError && (
            <Alert variant="destructive">
              <AlertDescription>{authError}</AlertDescription>
            </Alert>
          )}
          {isSsoConfigured ? (
            <div className="flex flex-col items-center gap-4">
              <GoogleLogin onSuccess={handleGoogleSuccess} onError={handleGoogleError} useOneTap={false} />
              {isAuthenticating && (
                <div className="flex items-center gap-2 text-sm text-slate-500">
                  <Loader2 className="size-4 animate-spin" />
                  <span>로그인 진행 중...</span>
                </div>
              )}
            </div>
          ) : (
            <Alert>
              <AlertDescription>
                Google SSO 클라이언트 ID가 설정되지 않았습니다. <code>VITE_GOOGLE_CLIENT_ID</code>와{' '}
                <code>GOOGLE_CLIENT_ID</code> 환경 변수를 구성하세요.
              </AlertDescription>
            </Alert>
          )}
          <div className="text-center">
            <Button
              type="button"
              variant="ghost"
              onClick={refreshSession}
              className="text-sm text-slate-500 hover:text-slate-800"
            >
              세션 다시 확인
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return <DashboardApp user={authUser} onLogout={handleLogout} />;
}

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '/api').replace(/\/$/, '');
const SELECTED_COMPETITION_KEY = 'ctf-hunter:selected-competition';
const SELECTED_PROBLEM_KEY = 'ctf-hunter:selected-problem';
const SELECTED_TAB_KEY = 'ctf-hunter:selected-tab';
// eslint-disable-next-line no-control-regex
const ANSI_CSI_REGEX = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
// eslint-disable-next-line no-control-regex
const ANSI_OSC_REGEX = /\u001b\][^\u0007]*\u0007/g;
const WRITEUP_CAPTURE_IDLE_MS = 1800;
const WRITEUP_CAPTURE_MAX_MS = 20000;
const WRITEUP_COMMAND = '1.한국어로 작성하고 writeup 코드 있다면 첨부 2.분석 배경은 설명하지말고 분석 방법 및 결과만 첨부 3.플래그는 정답:플래그 형식으로 적어줘 4.writeup 작성 시 맨 위에 문제 이름을 말하고 작성해줘 ';

const stripAnsi = (value: string) => {
  if (typeof value !== 'string') {
    return '';
  }
  return value.replace(ANSI_CSI_REGEX, '').replace(ANSI_OSC_REGEX, '');
};

const FLAG_LINE_REGEX = /정답\s*[:：]\s*([^\n]+)/i;
const FLAG_WRAPPED_REGEX = /FLAG\{[^}\s]+\}/i;

const normalizeWriteupText = (value: string, options?: { problemTitle?: string }) => {
  if (!value) return '';
  const sanitized = stripAnsi(value).replace(/\r/g, '');
  const lines = sanitized.split('\n');
  let skippedEcho = false;
  let contentStarted = false;

  const shouldDropPromptLine = (rawLine: string) => {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      return !contentStarted;
    }
    const normalized = trimmed.replace(/^›\s*/, '').toLowerCase();
    const isCommandEcho = normalized.startsWith('$ writeup') || normalized.startsWith('writeup 작성');
    if (!skippedEcho && isCommandEcho) {
      skippedEcho = true;
      return true;
    }
    if (!contentStarted) {
      if (
        normalized.includes('explain this codebase') ||
        normalized.includes('? for shortcuts') ||
        normalized.startsWith('working') ||
        normalized.includes('preparing writeup') ||
        normalized.includes('writeup 코드')
      ) {
        return true;
      }
    }
    return false;
  };

  const filteredLines = lines
    .map((line) => line.replace(/\s+$/, ''))
    .filter((line) => {
      if (shouldDropPromptLine(line)) {
        return false;
      }
      const trimmed = line.trim();
      if (!trimmed && !contentStarted) {
        return false;
      }
      if (/^\[system\]/i.test(trimmed)) {
        return false;
      }
      if (!contentStarted && trimmed) {
        contentStarted = true;
      }
      return true;
    });

  const findWorkedForIndex = () => {
    for (let index = filteredLines.length - 1; index >= 0; index -= 1) {
      const candidate = filteredLines[index]?.toLowerCase() ?? '';
      if (candidate.includes('worked for')) {
        return index;
      }
    }
    return -1;
  };

  const workedIndex = findWorkedForIndex();
  let processedLines = filteredLines;
  if (workedIndex >= 0 && workedIndex < filteredLines.length - 1) {
    processedLines = filteredLines.slice(workedIndex + 1);
  }
  if (processedLines.length === 0) {
    processedLines = filteredLines;
  }

  const applyProblemTitleSplit = (linesToProcess: string[]) => {
    const problemTitle = options?.problemTitle?.trim();
    if (!problemTitle) return linesToProcess;
    const normalizedTitle = problemTitle.toLowerCase();
    const matchesTitleLine = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return false;
      const lower = trimmed.toLowerCase();
      if (lower === normalizedTitle) return true;
      const withoutPrefix = lower.replace(/^문제\s*(?:이름)?\s*[:：]\s*/, '');
      if (withoutPrefix === normalizedTitle) return true;
      return lower.includes(normalizedTitle);
    };
    const index = linesToProcess.findIndex((line) => matchesTitleLine(line));
    if (index >= 0 && index < linesToProcess.length - 1) {
      return linesToProcess.slice(index + 1);
    }
    return linesToProcess;
  };

  const afterTitleSplit = applyProblemTitleSplit(processedLines);
  if (afterTitleSplit.length > 0 && afterTitleSplit !== processedLines) {
    processedLines = afterTitleSplit;
  }

  if (processedLines.length === 0) {
    processedLines = filteredLines;
  }

  return processedLines.join('\n').trim();
};

const sanitizeFlagToken = (token: string) => {
  if (!token) return '';
  let result = token.trim();
  result = result.replace(/^["'`]+/, '').replace(/["'`]+$/, '');
  result = result.replace(/^\[+/, '').replace(/\]+$/, '');
  result = result.replace(/^\(+/, '').replace(/\)+$/, '');
  const firstBraceIndex = result.indexOf('{');
  if (firstBraceIndex >= 0) {
    let depth = 0;
    let closingBraceIndex = -1;
    for (let index = firstBraceIndex; index < result.length; index += 1) {
      const char = result[index];
      if (char === '{') {
        depth += 1;
      } else if (char === '}') {
        depth -= 1;
        if (depth === 0) {
          closingBraceIndex = index;
          break;
        }
      }
    }
    if (closingBraceIndex >= 0) {
      result = result.slice(0, closingBraceIndex + 1);
    }
  } else {
    const fallbackIndex = result.lastIndexOf('}');
    if (fallbackIndex >= 0) {
      result = result.slice(0, fallbackIndex + 1);
    }
  }
  return result.trim();
};

const extractFlagFromWriteup = (value: string) => {
  if (!value) return null;
  const explicit = value.match(FLAG_LINE_REGEX);
  if (explicit?.[1]) {
    const sanitized = sanitizeFlagToken(explicit[1].split(/\r?\n/)[0] ?? '').trim();
    if (sanitized) {
      const inlineFlag = sanitized.match(FLAG_WRAPPED_REGEX);
      if (inlineFlag?.[0]) {
        return inlineFlag[0].trim();
      }
      return sanitized;
    }
  }
  const wrapped = value.match(FLAG_WRAPPED_REGEX);
  if (wrapped?.[0]) {
    return wrapped[0].trim();
  }
  return null;
};

function DashboardApp({ user, onLogout }: DashboardAppProps) {
  const [competitions, setCompetitions] = useState<Competition[]>([]);
  const [selectedCompetition, setSelectedCompetition] = useState<Competition | null>(null);
  const [selectedProblem, setSelectedProblem] = useState<CTFProblem | null>(null);
  const [problems, setProblems] = useState<CTFProblem[]>([]);
  const [isLoadingCompetitions, setIsLoadingCompetitions] = useState(true);
  const [isLoadingProblems, setIsLoadingProblems] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'problems' | 'admin' | 'terminal'>('problems');
  const [pendingProblemId, setPendingProblemId] = useState<string | null>(null);
  type SessionCommand = { id: number; command: string; appendNewline?: boolean; autoSubmit?: boolean; echo?: boolean };
  type ProblemSession = { problemId: string; problemTitle: string; sessionKey: string; serverSessionId?: string | null };
  type WriteupRequestState = {
    status: 'idle' | 'recording' | 'saving' | 'success' | 'error';
    message?: string;
  };

  const [activeSessions, setActiveSessions] = useState<ProblemSession[]>([]);
  const ACTIVE_SESSIONS_KEY_PREFIX = 'ctf-hunter:active-sessions:';
  const getSessionsStorageKey = useCallback((competitionId?: string | null) => (
    competitionId ? `${ACTIVE_SESSIONS_KEY_PREFIX}${competitionId}` : `${ACTIVE_SESSIONS_KEY_PREFIX}__none__`
  ), []);
  const [sessionCommands, setSessionCommands] = useState<Record<string, SessionCommand | null>>({});
  const cliCommandCounter = useRef(0);
  const [writeupRequestStates, setWriteupRequestStates] = useState<Record<string, WriteupRequestState>>({});
  const writeupCaptureActiveRef = useRef<Record<string, boolean>>({});
  const writeupBufferRef = useRef<Record<string, string>>({});
  const writeupIdleTimersRef = useRef<Record<string, ReturnType<typeof setTimeout> | null>>({});
  const writeupGlobalTimersRef = useRef<Record<string, ReturnType<typeof setTimeout> | null>>({});

  const clearWriteupTimers = useCallback((problemId: string) => {
    const idleTimer = writeupIdleTimersRef.current[problemId];
    if (idleTimer) {
      clearTimeout(idleTimer);
      writeupIdleTimersRef.current[problemId] = null;
    }
    const globalTimer = writeupGlobalTimersRef.current[problemId];
    if (globalTimer) {
      clearTimeout(globalTimer);
      writeupGlobalTimersRef.current[problemId] = null;
    }
  }, []);

  const finalizeWriteupCapture = useCallback((problemId: string, options?: { reason?: 'timeout' }) => {
    if (!writeupCaptureActiveRef.current[problemId]) {
      return;
    }
    delete writeupCaptureActiveRef.current[problemId];
    clearWriteupTimers(problemId);
    const raw = writeupBufferRef.current[problemId] ?? '';
    const currentProblem = problems.find((item) => item.id === problemId);
    const cleaned = normalizeWriteupText(raw, { problemTitle: currentProblem?.title });
    const parsedFlag = extractFlagFromWriteup(cleaned);

    if (!cleaned) {
      setWriteupRequestStates((prev) => ({
        ...prev,
        [problemId]: {
          status: 'error',
          message: options?.reason === 'timeout'
            ? '세션 응답을 받지 못했습니다.'
            : 'AI 답변을 찾지 못했습니다.',
        },
      }));
      return;
    }

    if (!selectedCompetition) {
      setWriteupRequestStates((prev) => ({
        ...prev,
        [problemId]: { status: 'error', message: '대회 정보가 없습니다.' },
      }));
      return;
    }

    setWriteupRequestStates((prev) => ({
      ...prev,
      [problemId]: { status: 'saving', message: 'AI 풀이를 저장하는 중입니다...' },
    }));

    const persist = async () => {
      try {
        const payload: Record<string, unknown> = { writeup: cleaned };
        if (parsedFlag) {
          payload.flag = parsedFlag;
        }
        const response = await fetch(
          `${API_BASE}/competitions/${selectedCompetition.id}/problems/${problemId}`,
          {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(payload),
          }
        );
        const data = await response.json();
        if (!response.ok || data.ok === false) {
          throw new Error(data.error ?? 'AI 풀이를 저장하지 못했습니다.');
        }
        const updatedProblem: CTFProblem = data.problem;
        setProblems((prev) => prev.map((item) => (item.id === updatedProblem.id ? updatedProblem : item)));
        setSelectedProblem((current) => (current?.id === updatedProblem.id ? updatedProblem : current));
        writeupBufferRef.current[problemId] = '';
        setWriteupRequestStates((prev) => ({
          ...prev,
          [problemId]: { status: 'success', message: 'AI 풀이를 저장했습니다.' },
        }));
      } catch (error) {
        setWriteupRequestStates((prev) => ({
          ...prev,
          [problemId]: {
            status: 'error',
            message: error instanceof Error ? error.message : 'AI 풀이를 저장하지 못했습니다.',
          },
        }));
      }
    };

    void persist();
  }, [clearWriteupTimers, selectedCompetition, setProblems, setSelectedProblem, problems]);

  const scheduleWriteupIdleTimer = useCallback((problemId: string) => {
    const existing = writeupIdleTimersRef.current[problemId];
    if (existing) {
      clearTimeout(existing);
    }
    writeupIdleTimersRef.current[problemId] = setTimeout(() => {
      finalizeWriteupCapture(problemId);
    }, WRITEUP_CAPTURE_IDLE_MS);
  }, [finalizeWriteupCapture]);

  const scheduleWriteupTimeout = useCallback((problemId: string) => {
    const existing = writeupGlobalTimersRef.current[problemId];
    if (existing) {
      clearTimeout(existing);
    }
    writeupGlobalTimersRef.current[problemId] = setTimeout(() => {
      finalizeWriteupCapture(problemId, { reason: 'timeout' });
    }, WRITEUP_CAPTURE_MAX_MS);
  }, [finalizeWriteupCapture]);

  const beginWriteupCapture = useCallback((problemId: string) => {
    clearWriteupTimers(problemId);
    writeupCaptureActiveRef.current[problemId] = true;
    writeupBufferRef.current[problemId] = '';
    scheduleWriteupTimeout(problemId);
  }, [clearWriteupTimers, scheduleWriteupTimeout]);

  const cancelActiveWriteupCapture = useCallback((problemId: string, message?: string) => {
    const wasActive = writeupCaptureActiveRef.current[problemId];
    if (wasActive) {
      delete writeupCaptureActiveRef.current[problemId];
    }
    clearWriteupTimers(problemId);
    writeupBufferRef.current[problemId] = '';
    if (wasActive) {
      setWriteupRequestStates((prev) => ({
        ...prev,
        [problemId]: {
          status: 'error',
          message: message ?? '세션이 종료되어 AI 풀이 수집을 중단했습니다.',
        },
      }));
    }
  }, [clearWriteupTimers]);

  const handleSessionOutput = useCallback((problemId: string, chunk: string) => {
    if (!writeupCaptureActiveRef.current[problemId]) {
      return;
    }
    const payload = typeof chunk === 'string' ? chunk : String(chunk ?? '');
    if (!payload) {
      return;
    }
    writeupBufferRef.current[problemId] = (writeupBufferRef.current[problemId] ?? '') + payload;
    scheduleWriteupIdleTimer(problemId);
    scheduleWriteupTimeout(problemId);
  }, [scheduleWriteupIdleTimer, scheduleWriteupTimeout]);
  const startSessionForProblem = useCallback((problem: CTFProblem) => {
    setActiveSessions((current) => {
      const existing = current.find((session) => session.problemId === problem.id);
      if (existing) {
        if (existing.problemTitle !== problem.title) {
          return current.map((session) =>
            session.problemId === problem.id ? { ...session, problemTitle: problem.title } : session
          );
        }
        return current;
      }
      const newSession: ProblemSession = {
        problemId: problem.id,
        problemTitle: problem.title,
        sessionKey: `${problem.id}-${Date.now()}`,
        serverSessionId: null,
      };
      return [...current, newSession];
    });
  }, []);

  const stopSessionForProblem = useCallback((problemId: string) => {
    cancelActiveWriteupCapture(problemId);
    setActiveSessions((current) => {
      const found = current.find((s) => s.problemId === problemId);
      if (found?.serverSessionId) {
        void fetch(`${API_BASE}/cli/sessions/${encodeURIComponent(found.serverSessionId)}`, {
          method: 'DELETE',
          credentials: 'include',
        }).catch(() => {});
      }
      return current.filter((session) => session.problemId !== problemId);
    });
    setSessionCommands((current) => {
      if (!(problemId in current)) {
        return current;
      }
      const next = { ...current };
      delete next[problemId];
      return next;
    });
  }, [cancelActiveWriteupCapture]);

  const fetchCompetitions = useCallback(async () => {
    setIsLoadingCompetitions(true);
    try {
      const response = await fetch(`${API_BASE}/competitions`, {
        credentials: 'include',
      });
      const data = await response.json();
      if (response.ok && data.ok) {
        setCompetitions(data.competitions ?? []);
      } else {
        throw new Error(data.error ?? 'CTF 대회 목록을 불러오지 못했습니다.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'CTF 대회 목록을 불러오지 못했습니다.');
    } finally {
      setIsLoadingCompetitions(false);
    }
  }, []);

  const handleCreateCompetition = useCallback(
    async (payload: { name: string; description?: string; isShared?: boolean }) => {
      const response = await fetch(`${API_BASE}/competitions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload),
      });
      const data = await response.json();

      if (!response.ok || data.ok === false) {
        throw new Error(data.error ?? 'CTF 대회를 생성하지 못했습니다.');
      }

      setCompetitions(prev => [data.competition, ...prev]);
      setSelectedCompetition(data.competition);
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(SELECTED_COMPETITION_KEY, data.competition.id);
      }
      setError(null);
    },
    []
  );

  const fetchProblems = useCallback(async (competitionId: string) => {
    setIsLoadingProblems(true);
    try {
      const response = await fetch(`${API_BASE}/competitions/${competitionId}/problems`, {
        credentials: 'include',
      });
      const data = await response.json();

      if (!response.ok || data.ok === false) {
        throw new Error(data.error ?? '문제 데이터를 불러오지 못했습니다.');
      }

      setProblems(data.problems ?? []);
      setError(null);
    } catch (err) {
      setProblems([]);
      setError(err instanceof Error ? err.message : '문제 데이터를 불러오지 못했습니다.');
    } finally {
      setIsLoadingProblems(false);
    }
  }, []);

  const handleCompetitionDeleted = useCallback(
    (competitionId: string) => {
      setCompetitions(prev => prev.filter(comp => comp.id !== competitionId));
      if (selectedCompetition?.id === competitionId) {
        setSelectedCompetition(null);
        setSelectedProblem(null);
        setProblems([]);
        if (typeof window !== 'undefined') {
          window.localStorage.removeItem(SELECTED_COMPETITION_KEY);
          window.localStorage.removeItem(SELECTED_PROBLEM_KEY);
        }
      }
    },
    [selectedCompetition]
  );

  const handleTabChange = useCallback((value: string) => {
    if (value === 'problems' || value === 'admin' || value === 'terminal') {
      setActiveTab(value);
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(SELECTED_TAB_KEY, value);
      }
    }
  }, []);

  const handleAiSolveRequest = useCallback(
    (targetProblem: CTFProblem, command: string) => {
      if (!command.trim()) return;
      startSessionForProblem(targetProblem);
      cliCommandCounter.current += 1;
      setSessionCommands((current) => ({
        ...current,
        [targetProblem.id]: { id: cliCommandCounter.current, command, appendNewline: false, autoSubmit: true },
      }));
    },
    [startSessionForProblem]
  );

  const handleAiWriteupRequest = useCallback(
    (targetProblem: CTFProblem) => {
      if (!selectedCompetition) {
        setWriteupRequestStates((prev) => ({
          ...prev,
          [targetProblem.id]: { status: 'error', message: '대회 정보가 없습니다.' },
        }));
        return;
      }
      const hasSession = activeSessions.some((session) => session.problemId === targetProblem.id);
      if (!hasSession) {
        setWriteupRequestStates((prev) => ({
          ...prev,
          [targetProblem.id]: { status: 'error', message: 'Codex 세션을 먼저 시작하세요.' },
        }));
        return;
      }
      beginWriteupCapture(targetProblem.id);
      setWriteupRequestStates((prev) => ({
        ...prev,
        [targetProblem.id]: { status: 'recording', message: '세션 응답을 수집하는 중입니다...' },
      }));
      cliCommandCounter.current += 1;
      setSessionCommands((current) => ({
        ...current,
        [targetProblem.id]: {
          id: cliCommandCounter.current,
          command: WRITEUP_COMMAND,
          appendNewline: true,
          autoSubmit: true,
          echo: false,
        },
      }));
    },
    [activeSessions, beginWriteupCapture, selectedCompetition]
  );

  const handleFlagSave = useCallback(
    async (problemId: string, flagValue: string) => {
      if (!selectedCompetition) {
        throw new Error('대회가 선택되지 않았습니다.');
      }
      const nextSolved = Boolean(flagValue.trim());
      const response = await fetch(
        `${API_BASE}/competitions/${selectedCompetition.id}/problems/${problemId}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ flag: flagValue, solved: nextSolved }),
        }
      );
      const data = await response.json();
      if (!response.ok || data.ok === false) {
        throw new Error(data.error ?? '플래그를 저장하지 못했습니다.');
      }
      const updatedProblem: CTFProblem = data.problem;
      setProblems((prev) => prev.map((item) => (item.id === updatedProblem.id ? updatedProblem : item)));
      setSelectedProblem((current) => (current?.id === updatedProblem.id ? updatedProblem : current));
    },
    [selectedCompetition]
  );

  // Persist and restore Codex sessions across reloads (per competition)

  useEffect(() => {
    fetchCompetitions();
  }, [fetchCompetitions]);

  useEffect(() => {
    setActiveSessions((current) => {
      if (current.length === 0) return current;
      let mutated = false;
      const next = current.reduce<ProblemSession[]>((acc, session) => {
        const latest = problems.find((problem) => problem.id === session.problemId);
        if (!latest) {
          mutated = true;
          return acc;
        }
        if (latest.title !== session.problemTitle) {
          mutated = true;
          acc.push({ ...session, problemTitle: latest.title });
        } else {
          acc.push(session);
        }
        return acc;
      }, []);
      return mutated ? next : current;
    });
  }, [problems]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const storedTab = window.localStorage.getItem(SELECTED_TAB_KEY);
    if (storedTab === 'problems' || storedTab === 'admin' || storedTab === 'terminal') {
      setActiveTab(storedTab);
    }
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (selectedCompetition) return;
    const storedId = window.localStorage.getItem(SELECTED_COMPETITION_KEY);
    if (!storedId) return;
    if (competitions.length === 0) return;
    const found = competitions.find((competition) => competition.id === storedId);
    if (found) {
      setSelectedCompetition(found);
    } else {
      window.localStorage.removeItem(SELECTED_COMPETITION_KEY);
    }
  }, [competitions, selectedCompetition]);

  useEffect(() => {
    if (selectedCompetition) {
      fetchProblems(selectedCompetition.id);
    } else {
      setProblems([]);
    }
  }, [selectedCompetition, fetchProblems]);

  // Restore active sessions for this competition
  useEffect(() => {
    if (!selectedCompetition) return;
    if (typeof window === 'undefined') return;
    try {
      const raw = window.localStorage.getItem(getSessionsStorageKey(selectedCompetition.id));
      if (raw) {
        const parsed = JSON.parse(raw) as ProblemSession[];
        if (Array.isArray(parsed)) {
          setActiveSessions(parsed);
        }
      }
    } catch {
      // ignore invalid storage
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCompetition?.id]);

  // Persist sessions whenever they change
  useEffect(() => {
    if (!selectedCompetition) return;
    if (typeof window === 'undefined') return;
    try {
      const key = getSessionsStorageKey(selectedCompetition.id);
      window.localStorage.setItem(key, JSON.stringify(activeSessions));
    } catch {
      // ignore
    }
  }, [activeSessions, selectedCompetition, getSessionsStorageKey]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (!selectedCompetition) {
      setPendingProblemId(null);
      return;
    }
    const stored = window.localStorage.getItem(SELECTED_PROBLEM_KEY);
    if (!stored) {
      setPendingProblemId(null);
      return;
    }
    try {
      const parsed = JSON.parse(stored) as { competitionId: string; problemId: string };
      if (parsed.competitionId === selectedCompetition.id) {
        setPendingProblemId(parsed.problemId);
      } else {
        setPendingProblemId(null);
      }
    } catch {
      window.localStorage.removeItem(SELECTED_PROBLEM_KEY);
      setPendingProblemId(null);
    }
  }, [selectedCompetition]);

  useEffect(() => {
    if (!pendingProblemId || isLoadingProblems) return;
    const found = problems.find(problem => problem.id === pendingProblemId);
    if (found) {
      setSelectedProblem(found);
      setPendingProblemId(null);
    } else {
      setPendingProblemId(null);
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem(SELECTED_PROBLEM_KEY);
      }
    }
  }, [pendingProblemId, problems, isLoadingProblems]);

  useEffect(() => {
    if (!selectedProblem) return;
    const updated = problems.find(problem => problem.id === selectedProblem.id);
    if (!updated) {
      setSelectedProblem(null);
    } else if (updated !== selectedProblem) {
      setSelectedProblem(updated);
    }
  }, [problems, selectedProblem]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (!selectedCompetition) return;
    if (selectedProblem) {
      window.localStorage.setItem(
        SELECTED_PROBLEM_KEY,
        JSON.stringify({ competitionId: selectedCompetition.id, problemId: selectedProblem.id })
      );
    } else if (!pendingProblemId) {
      window.localStorage.removeItem(SELECTED_PROBLEM_KEY);
    }
  }, [selectedCompetition, selectedProblem, pendingProblemId]);

  useEffect(() => {
    // 유지 중인 세션은 복원 로직에서 다시 설정하므로 여기서는 비우지 않습니다.
    setSessionCommands({});
    const timerKeys = new Set([
      ...Object.keys(writeupIdleTimersRef.current ?? {}),
      ...Object.keys(writeupGlobalTimersRef.current ?? {}),
    ]);
    timerKeys.forEach((problemId) => clearWriteupTimers(problemId));
    writeupCaptureActiveRef.current = {};
    writeupBufferRef.current = {};
    writeupIdleTimersRef.current = {};
    writeupGlobalTimersRef.current = {};
    setWriteupRequestStates({});
  }, [selectedCompetition?.id, clearWriteupTimers]);

  const handleCompetitionSelect = (competition: Competition) => {
    setSelectedCompetition(competition);
    setSelectedProblem(null);
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(SELECTED_COMPETITION_KEY, competition.id);
      window.localStorage.removeItem(SELECTED_PROBLEM_KEY);
    }
  };

  const clearCompetitionSelection = () => {
    setSelectedCompetition(null);
    setSelectedProblem(null);
    if (typeof window !== 'undefined') {
      window.localStorage.removeItem(SELECTED_COMPETITION_KEY);
      window.localStorage.removeItem(SELECTED_PROBLEM_KEY);
    }
  };

  const handleProblemSelect = (problem: CTFProblem) => {
    setSelectedProblem(problem);
    if (typeof window !== 'undefined' && selectedCompetition) {
      window.localStorage.setItem(
        SELECTED_PROBLEM_KEY,
        JSON.stringify({ competitionId: selectedCompetition.id, problemId: problem.id })
      );
    }
  };

  const handleToggleSolved = async (problemId: string) => {
    if (!selectedCompetition) return;
    const problem = problems.find(p => p.id === problemId);
    if (!problem) return;

    const nextSolved = !problem.solved;
    const previousProblems = problems;

    setProblems(prev =>
      prev.map(item => (item.id === problemId ? { ...item, solved: nextSolved } : item))
    );
    if (selectedProblem?.id === problemId) {
      setSelectedProblem({ ...problem, solved: nextSolved });
    }

    try {
      const response = await fetch(
        `${API_BASE}/competitions/${selectedCompetition.id}/problems/${problemId}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ solved: nextSolved }),
        }
      );
      const data = await response.json();
      if (!response.ok || data.ok === false) {
        throw new Error(data.error ?? '문제 상태를 업데이트하지 못했습니다.');
      }

      const updatedProblem: CTFProblem = data.problem;
      setProblems(prev =>
        prev.map(item => (item.id === updatedProblem.id ? updatedProblem : item))
      );
      if (selectedProblem?.id === updatedProblem.id) {
        setSelectedProblem(updatedProblem);
      }
      setError(null);
    } catch (err) {
      setProblems(previousProblems);
      if (selectedProblem?.id === problemId) {
        const previous = previousProblems.find(p => p.id === problemId) ?? null;
        setSelectedProblem(previous);
      }
      setError(err instanceof Error ? err.message : '문제 상태를 업데이트하지 못했습니다.');
    }
  };

  if (!selectedCompetition) {
    return (
      <div className="min-h-screen bg-slate-50">
        <div className="border-b border-slate-200 bg-white">
          <div className="container mx-auto px-6 py-4">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-slate-900 rounded-lg">
                  <Flag className="size-5 text-white" />
                </div>
                <div>
                  <h1 className="text-slate-900">AUTOCTF</h1>
                  <p className="text-slate-600 text-sm">참여할 대회를 선택하세요.</p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <p className="text-sm font-semibold text-slate-900">{user.name ?? user.email}</p>
                  <p className="text-xs text-slate-500">{user.email}</p>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  className="border-slate-300 text-slate-700"
                  onClick={() => {
                    void onLogout();
                  }}
                >
                  <LogOut className="size-3 mr-1" />
                  로그아웃
                </Button>
              </div>
            </div>
          </div>
        </div>
        <div className="container mx-auto px-6 py-8">
          <CompetitionSelector
            competitions={competitions}
            isLoading={isLoadingCompetitions}
            onRefresh={fetchCompetitions}
            onSelect={handleCompetitionSelect}
            onCreate={handleCreateCompetition}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <div className="border-b border-slate-200 bg-white">
        <div className="container mx-auto px-6 py-4">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-slate-900 rounded-lg">
                <Flag className="size-5 text-white" />
              </div>
              <div>
                <h1 className="text-slate-900">AUTOCTF</h1>
                <p className="text-slate-600 text-sm">
                  {selectedCompetition.name} · 등록된 문제 {problems.length}개
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <p className="text-sm font-semibold text-slate-900">{user.name ?? user.email}</p>
                <p className="text-xs text-slate-500">{user.email}</p>
              </div>
              <Button
                type="button"
                variant="outline"
                className="border-slate-300 text-slate-700"
                onClick={() => {
                  void onLogout();
                }}
              >
                <LogOut className="size-3 mr-1" />
                로그아웃
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={clearCompetitionSelection}
                className="border-slate-300 text-slate-700"
              >
                다른 대회 선택
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-6 py-8 space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-6">
          <TabsList className="bg-white border border-slate-200">
            <TabsTrigger 
              value="problems"
              className="data-[state=active]:bg-slate-900 data-[state=active]:text-white transition-all duration-200 active:scale-95"
            >
              <List className="size-4 mr-2" />
              문제 목록
            </TabsTrigger>
            <TabsTrigger 
              value="admin"
              className="data-[state=active]:bg-slate-900 data-[state=active]:text-white transition-all duration-200 active:scale-95"
            >
              <Settings className="size-4 mr-2" />
              관리자 패널
            </TabsTrigger>
            <TabsTrigger 
              value="terminal"
              className="data-[state=active]:bg-slate-900 data-[state=active]:text-white transition-all duration-200 active:scale-95"
            >
              <TerminalIcon className="size-4 mr-2" />
              CLI 환경
            </TabsTrigger>
          </TabsList>

          <TabsContent value="problems" className="space-y-6">
            {isLoadingProblems && (
              <div className="flex items-center gap-2 text-slate-600 text-sm">
                <Loader2 className="size-4 animate-spin" />
                문제 데이터를 불러오는 중입니다...
              </div>
            )}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="lg:col-span-1">
                <CTFProblemList 
                  selectedProblem={selectedProblem}
                  onSelectProblem={handleProblemSelect}
                  onToggleSolved={handleToggleSolved}
                  problems={problems}
                />
              </div>

              <div className="lg:col-span-1">
                <ProblemDetail
                  problem={selectedProblem}
                  competitionId={selectedCompetition.id}
                  onAiSolveRequest={handleAiSolveRequest}
                  onAiWriteupRequest={handleAiWriteupRequest}
                  onStartSession={(problem) => {
                    startSessionForProblem(problem);
                  }}
                  onStopSession={(problemId) => stopSessionForProblem(problemId)}
                  isSessionActive={Boolean(
                    selectedProblem && activeSessions.some((session) => session.problemId === selectedProblem.id)
                  )}
                  onFlagSave={handleFlagSave}
                  writeupStatus={selectedProblem ? writeupRequestStates[selectedProblem.id] : undefined}
                />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="admin">
            <AdminPanel 
              competitionId={selectedCompetition.id}
              competitionName={selectedCompetition.name}
              onProblemsUpdate={setProblems}
              currentProblems={problems}
              onRefreshProblems={() => fetchProblems(selectedCompetition.id)}
              onCompetitionDeleted={handleCompetitionDeleted}
            />
          </TabsContent>

          <TabsContent value="terminal" forceMount>
            <div className="space-y-6">
              {activeSessions.length === 0 ? (
                <div className="bg-white border border-dashed border-slate-300 rounded-lg p-8 text-center text-slate-500">
                  <p className="text-lg font-medium text-slate-700 mb-2">활성화된 Codex 세션이 없습니다.</p>
                  <p className="text-sm">문제 상세 화면에서 &quot;Codex 세션 시작&quot; 버튼을 눌러 문제별 세션을 생성하세요.</p>
                </div>
              ) : (
                activeSessions.map((session) => {
                  const commandRequest = sessionCommands[session.problemId] ?? null;
                  return (
                    <div key={session.sessionKey} className="space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <p className="text-xs uppercase tracking-wide text-slate-500">문제 세션</p>
                          <h3 className="text-slate-900 font-semibold">{session.problemTitle}</h3>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            className="border-slate-300 text-slate-700"
                            onClick={() => {
                              const problem = problems.find((item) => item.id === session.problemId);
                              if (problem) {
                                setSelectedProblem(problem);
                                handleTabChange('problems');
                              }
                            }}
                          >
                            <ArrowUpRight className="size-3 mr-1" /> 문제 보기
                          </Button>
                          <Button
                            type="button"
                            variant="destructive"
                            size="sm"
                            onClick={() => stopSessionForProblem(session.problemId)}
                          >
                            <Power className="size-3 mr-1" /> 세션 종료
                          </Button>
                        </div>
                      </div>
                      <Terminal
                        sessionName={`Codex 인터랙티브 CLI · ${session.problemTitle}`}
                        sessionId={session.serverSessionId ?? null}
                        commandRequest={commandRequest}
                        onCommandHandled={(handledId) => {
                          setSessionCommands((current) => {
                            const entry = current[session.problemId];
                            if (!entry || entry.id !== handledId) {
                              return current;
                            }
                            const next = { ...current };
                            delete next[session.problemId];
                            return next;
                          });
                        }}
                        onOutput={(chunk) => handleSessionOutput(session.problemId, chunk)}
                        onSessionReady={(serverSessionId) => {
                          setActiveSessions((current) =>
                            current.map((s) =>
                              s.problemId === session.problemId ? { ...s, serverSessionId } : s
                            )
                          );
                        }}
                        onSessionExit={() => {
                          cancelActiveWriteupCapture(session.problemId, '세션이 종료되었습니다.');
                          setActiveSessions((current) => current.filter((s) => s.problemId !== session.problemId));
                        }}
                      />
                    </div>
                  );
                })
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
