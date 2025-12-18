import { useCallback, useEffect, useRef, useState, type ChangeEvent, type Dispatch, type SetStateAction } from 'react';
import { Card } from './ui/card';
import { Input } from './ui/input';
import { Button } from './ui/button';
import { Label } from './ui/label';
import { Alert, AlertDescription } from './ui/alert';
import { Badge } from './ui/badge';
import { ScrollArea } from './ui/scroll-area';
import { Textarea } from './ui/textarea';
import { Settings, Play, RotateCcw, Loader2, CheckCircle2, AlertCircle, Link as LinkIcon, Trash2, Upload, FileJson } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { CTFProblem } from '../App';

interface AdminPanelProps {
  competitionId: string;
  competitionName: string;
  onProblemsUpdate: Dispatch<SetStateAction<CTFProblem[]>>;
  onRefreshProblems: () => Promise<void> | void;
  currentProblems: CTFProblem[];
  onCompetitionDeleted: (competitionId: string) => void;
}

interface CrawlLog {
  timestamp: Date;
  type: 'info' | 'success' | 'error';
  message: string;
}

const apiBase = (import.meta.env.VITE_API_BASE_URL ?? '/api').replace(/\/$/, '');
const manualCategoryOptions = ['Web', 'Pwnable', 'Crypto', 'Forensics', 'Reversing', 'Misc'];

const formatFileSize = (bytes: number) => {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const precision = unit === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(precision)} ${units[unit]}`;
};

export function AdminPanel({
  competitionId,
  competitionName,
  onProblemsUpdate,
  onRefreshProblems,
  currentProblems,
  onCompetitionDeleted,
}: AdminPanelProps) {
  const [ctfUrl, setCtfUrl] = useState('');
  const [databaseName, setDatabaseName] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [isSettingsLoading, setIsSettingsLoading] = useState(false);
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [settingsReady, setSettingsReady] = useState(false);
  const [settingsDirty, setSettingsDirty] = useState(false);
  const [lastSavedAt, setLastSavedAt] = useState<Date | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [isCrawling, setIsCrawling] = useState(false);
  const [isDeletingCompetition, setIsDeletingCompetition] = useState(false);
  const [crawlLogs, setCrawlLogs] = useState<CrawlLog[]>([]);
  const [manualFile, setManualFile] = useState<File | null>(null);
  const manualFileInputRef = useRef<HTMLInputElement | null>(null);
  const [manualProblemTitle, setManualProblemTitle] = useState('');
  const [manualProblemDescription, setManualProblemDescription] = useState('');
  const [manualCategory, setManualCategory] = useState('Misc');
  const [manualReplaceExisting, setManualReplaceExisting] = useState(false);
  const [isManualUploading, setIsManualUploading] = useState(false);

  const addLog = useCallback((type: 'info' | 'success' | 'error', message: string) => {
    setCrawlLogs(prev => [...prev, { timestamp: new Date(), type, message }]);
  }, []);

  const saveSettings = useCallback(
    async (silent = false) => {
      if (!competitionId || !settingsReady) return null;
      setIsSavingSettings(true);
      try {
        const response = await fetch(`${apiBase}/competitions/${competitionId}/settings`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            ctfUrl,
            databaseName,
            apiKey,
          }),
        });
        const data = await response.json();
        if (!response.ok || data.ok === false) {
          throw new Error(data.error ?? '설정을 저장하지 못했습니다.');
        }
        setSettingsDirty(false);
        setLastSavedAt(new Date());
        if (!silent) {
          addLog('success', '관리자 설정이 저장되었습니다.');
        }
        return data.settings;
      } catch (error) {
        if (!silent) {
          addLog('error', error instanceof Error ? error.message : '설정을 저장하지 못했습니다.');
        }
        throw error;
      } finally {
        setIsSavingSettings(false);
      }
    },
    [competitionId, settingsReady, ctfUrl, databaseName, apiKey, addLog]
  );

  useEffect(() => {
    let cancelled = false;
    const fetchSettings = async () => {
      if (!competitionId) return;
      setIsSettingsLoading(true);
      setSettingsReady(false);
      setSettingsDirty(false);
      try {
        const response = await fetch(`${apiBase}/competitions/${competitionId}/settings`, {
          credentials: 'include',
        });
        const data = await response.json();
        if (!response.ok || data.ok === false) {
          throw new Error(data.error ?? '설정 정보를 불러오지 못했습니다.');
        }
        if (cancelled) return;
        const settings = data.settings ?? {};
        setCtfUrl(settings.ctfUrl ?? '');
        setDatabaseName(settings.databaseName ?? '');
        setApiKey(settings.apiKey ?? '');
        setLastSavedAt(
          settings.ctfUrl || settings.databaseName || settings.apiKey ? new Date() : null
        );
      } catch (error) {
        if (cancelled) return;
        addLog('error', error instanceof Error ? error.message : '설정 정보를 불러오지 못했습니다.');
        setCtfUrl('');
        setDatabaseName('');
        setApiKey('');
        setLastSavedAt(null);
      } finally {
        if (!cancelled) {
          setIsSettingsLoading(false);
          setSettingsReady(true);
          setSettingsDirty(false);
        }
      }
    };

    fetchSettings();
    return () => {
      cancelled = true;
    };
  }, [competitionId, addLog]);

  useEffect(() => {
    setManualFile(null);
    setManualReplaceExisting(false);
    setManualProblemTitle('');
    setManualProblemDescription('');
    setManualCategory('Misc');
    if (manualFileInputRef.current) {
      manualFileInputRef.current.value = '';
    }
  }, [competitionId]);

  useEffect(() => {
    if (!settingsReady || !settingsDirty) return;
    const timeout = setTimeout(() => {
      saveSettings(true).catch((error) => {
        addLog('error', error instanceof Error ? error.message : '설정을 저장하지 못했습니다.');
      });
    }, 1000);
    return () => clearTimeout(timeout);
  }, [settingsReady, settingsDirty, ctfUrl, databaseName, apiKey, saveSettings, addLog]);

  const persistProblems = async (problemsToPersist: CTFProblem[]) => {
    const response = await fetch(`${apiBase}/competitions/${competitionId}/problems/bulk`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        problems: problemsToPersist.map(problem => ({
          title: problem.title,
          description: problem.description,
          category: problem.category,
          difficulty: problem.difficulty,
          points: problem.points,
          files: problem.files,
          solved: problem.solved,
          source: problem.source,
        })),
      }),
    });

    const data = await response.json();

    if (!response.ok || data.ok === false) {
      throw new Error(data.error ?? '문제 데이터를 저장하지 못했습니다.');
    }

    return data.problems ?? [];
  };

  const importProblemsFromCtfd = async () => {
    addLog('info', 'CTFd API에서 문제 목록을 가져오는 중입니다...');
    const response = await fetch(`${apiBase}/competitions/${competitionId}/import/ctfd`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        baseUrl: ctfUrl,
        apiKey: apiKey.trim() || undefined,
        replaceExisting: true,
      }),
    });
    const data = await response.json();

    if (!response.ok || data.ok === false) {
      throw new Error(data.error ?? 'CTFd 문제를 가져오지 못했습니다.');
    }

    const importedCount = data.imported ?? (data.problems?.length ?? 0);
    addLog('success', `${importedCount}개의 문제를 CTFd에서 불러왔습니다.`);
    if (Array.isArray(data.problems)) {
      onProblemsUpdate(() => data.problems ?? []);
    }
    await Promise.resolve(onRefreshProblems());
  };

  const runMockCrawl = async () => {
    await new Promise(resolve => setTimeout(resolve, 1000));
    addLog('info', '사이트 연결 중...');

    await new Promise(resolve => setTimeout(resolve, 1500));
    
    addLog('success', '사이트 연결 성공!');

    await new Promise(resolve => setTimeout(resolve, 1000));
    addLog('info', '문제 목록 파싱 중...');

    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const mockProblems: CTFProblem[] = [
      {
        id: `crawl-${Date.now()}-1`,
        title: 'SQL Injection Challenge',
        category: 'Web',
        normalizedCategory: 'Web',
        difficulty: 'Medium',
        points: 250,
        description: '로그인 폼에서 SQL Injection 취약점을 찾아 관리자 권한을 획득하세요.',
        hints: [],
        files: [],
        solved: false,
        source: ctfUrl,
        createdAt: new Date().toISOString()
      },
      {
        id: `crawl-${Date.now()}-2`,
        title: 'Buffer Overflow Exploit',
        category: 'Pwnable',
        normalizedCategory: 'Pwnable',
        difficulty: 'Hard',
        points: 400,
        description: 'C 프로그램의 버퍼 오버플로우를 이용하여 쉘을 획득하세요.',
        hints: [],
        files: [],
        solved: false,
        source: ctfUrl,
        createdAt: new Date().toISOString()
      },
      {
        id: `crawl-${Date.now()}-3`,
        title: 'Caesar Cipher Decoder',
        category: 'Crypto',
        normalizedCategory: 'Crypto',
        difficulty: 'Easy',
        points: 100,
        description: '시저 암호로 암호화된 메시지를 복호화하세요.',
        hints: [],
        files: [],
        solved: false,
        source: ctfUrl,
        createdAt: new Date().toISOString()
      },
      {
        id: `crawl-${Date.now()}-4`,
        title: 'Steganography Image',
        category: 'Forensics',
        normalizedCategory: 'Forensics',
        difficulty: 'Medium',
        points: 200,
        description: '이미지 파일에 숨겨진 플래그를 찾으세요.',
        hints: [],
        files: [],
        solved: false,
        source: ctfUrl,
        createdAt: new Date().toISOString()
      },
      {
        id: `crawl-${Date.now()}-5`,
        title: 'XSS Vulnerability',
        category: 'Web',
        normalizedCategory: 'Web',
        difficulty: 'Easy',
        points: 150,
        description: '게시판에서 XSS 취약점을 찾아 쿠키를 탈취하세요.',
        hints: [],
        solved: false,
        source: ctfUrl,
        createdAt: new Date().toISOString()
      },
      {
        id: `crawl-${Date.now()}-6`,
        title: 'Reverse Engineering Binary',
        category: 'Reversing',
        normalizedCategory: 'Reversing',
        difficulty: 'Hard',
        points: 350,
        description: '바이너리를 리버스 엔지니어링하여 플래그 검증 로직을 분석하세요.',
        hints: [],
        files: [],
        solved: false,
        source: ctfUrl,
        createdAt: new Date().toISOString()
      }
    ];

    addLog('success', `${mockProblems.length}개의 문제를 발견했습니다.`);
    
    await new Promise(resolve => setTimeout(resolve, 500));
    addLog('info', '문제 데이터 저장 중...');

    const savedProblems = await persistProblems(mockProblems);
    onProblemsUpdate(() => savedProblems ?? []);
    await Promise.resolve(onRefreshProblems());
    
    addLog('success', '크롤링 완료! 문제가 성공적으로 추가되었습니다.');
  };

  const handleStartCTF = async () => {
    if (!ctfUrl.trim() || !databaseName.trim() || !apiKey.trim()) {
      addLog('error', 'CTF 사이트 URL, 데이터베이스 이름, API Key를 모두 입력해주세요.');
      return;
    }

    try {
      await saveSettings(true);
    } catch (error) {
      addLog('error', error instanceof Error ? error.message : '설정을 저장하지 못했습니다.');
      return;
    }

    setIsCrawling(true);
    setIsRunning(true);
    addLog('info', `크롤링 시작: ${ctfUrl}`);
    if (databaseName.trim()) {
      addLog('info', `대상 데이터베이스: ${databaseName}`);
    }
    if (apiKey.trim()) {
      addLog('info', 'CTFd API Key 인증 사용');
    }

    try {
      if (apiKey.trim()) {
        await importProblemsFromCtfd();
      } else {
        await runMockCrawl();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : '크롤링 중 오류가 발생했습니다.';
      addLog('error', message);
    } finally {
      setIsCrawling(false);
      setIsRunning(false);
    }
  };

  const handleResetCTF = async () => {
    if (!ctfUrl.trim() || !databaseName.trim() || !apiKey.trim()) {
      addLog('error', 'CTF 사이트 URL, 데이터베이스 이름, API Key를 모두 입력해주세요.');
      return;
    }

    try {
      await saveSettings(true);
    } catch (error) {
      addLog('error', error instanceof Error ? error.message : '설정을 저장하지 못했습니다.');
      return;
    }

    setIsCrawling(true);
    addLog('info', `CTF 문제 갱신 시작: ${ctfUrl}`);
    if (databaseName.trim()) {
      addLog('info', `대상 데이터베이스: ${databaseName}`);
    }
    if (apiKey.trim()) {
      addLog('info', 'CTFd API Key 인증 사용');
    }

    try {
      await importProblemsFromCtfd();
      addLog('success', 'CTF 문제가 갱신되었습니다.');
    } catch (error) {
      const message = error instanceof Error ? error.message : '문제를 갱신하는 중 오류가 발생했습니다.';
      addLog('error', message);
    } finally {
      setIsCrawling(false);
    }
  };

  const handleDeleteCompetition = async () => {
    const confirmed = window.confirm('정말 이 CTF 대회를 삭제하시겠습니까? 저장된 문제와 파일이 모두 삭제됩니다.');
    if (!confirmed) {
      return;
    }
    setIsDeletingCompetition(true);
    try {
      const response = await fetch(`${apiBase}/competitions/${competitionId}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) {
        throw new Error(data.error ?? 'CTF 대회를 삭제하지 못했습니다.');
      }
      addLog('success', 'CTF 대회가 삭제되었습니다.');
      await Promise.resolve(onCompetitionDeleted(competitionId));
    } catch (error) {
      addLog('error', error instanceof Error ? error.message : 'CTF 대회 삭제에 실패했습니다.');
    } finally {
      setIsDeletingCompetition(false);
    }
  };

  const handleManualFileChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setManualFile(file);
  }, []);

  const handleManualUpload = useCallback(async () => {
    if (!competitionId) {
      addLog('error', '먼저 대회를 선택해주세요.');
      return;
    }
    const hasTitle = manualProblemTitle.trim().length > 0;
    const hasDescription = manualProblemDescription.trim().length > 0;
    if (!manualFile && (!hasTitle || !hasDescription)) {
      addLog('error', '파일 없이 업로드하려면 문제 이름과 설명이 모두 필요합니다.');
      return;
    }

    setIsManualUploading(true);
    addLog('info', manualFile ? `${manualFile.name} 업로드를 시작합니다.` : '업로드를 시작합니다.');

    try {
      const formData = new FormData();
      if (manualFile) {
        formData.append('archive', manualFile);
      }
      formData.append('replaceExisting', manualReplaceExisting ? 'true' : 'false');
      formData.append('category', manualCategory);
      if (manualProblemTitle.trim()) {
        formData.append('problemTitle', manualProblemTitle.trim());
      }
      if (manualProblemDescription.trim()) {
        formData.append('problemDescription', manualProblemDescription.trim());
      }

      const response = await fetch(`${apiBase}/competitions/${competitionId}/import/manual`, {
        method: 'POST',
        body: formData,
        credentials: 'include',
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) {
        throw new Error(data.error ?? '문제 업로드에 실패했습니다.');
      }

      addLog('success', `수동 업로드 완료: ${data.imported ?? 0}개 추가, ${data.updated ?? 0}개 갱신`);
      if (Array.isArray(data.warnings)) {
        data.warnings.forEach((warning: string) => {
          if (typeof warning === 'string' && warning.trim()) {
            addLog('info', warning);
          }
        });
      }
      if (Array.isArray(data.skipped)) {
        data.skipped.forEach((item: { title?: string; index?: number; reason?: string }) => {
          const label = item?.title || (typeof item?.index === 'number' ? `#${item.index}` : '알 수 없는 문제');
          addLog('error', `건너뜀 (${label}): ${item?.reason ?? '사유 없음'}`);
        });
      }
      if (Array.isArray(data.problems)) {
        onProblemsUpdate(() => data.problems ?? []);
      }
      await Promise.resolve(onRefreshProblems());
      setManualFile(null);
      setManualProblemTitle('');
      setManualProblemDescription('');
      setManualCategory('Misc');
      if (manualFileInputRef.current) {
        manualFileInputRef.current.value = '';
      }
    } catch (error) {
      addLog('error', error instanceof Error ? error.message : '문제 업로드에 실패했습니다.');
    } finally {
      setIsManualUploading(false);
    }
  }, [competitionId, manualFile, manualReplaceExisting, manualProblemTitle, manualProblemDescription, manualCategory, onProblemsUpdate, onRefreshProblems, addLog]);

  const getLogIcon = (type: string) => {
    switch (type) {
      case 'success': return <CheckCircle2 className="size-4 text-green-600" />;
      case 'error': return <AlertCircle className="size-4 text-red-600" />;
      default: return <AlertCircle className="size-4 text-blue-600" />;
    }
  };

  const getLogColor = (type: string) => {
    switch (type) {
      case 'success': return 'text-green-700';
      case 'error': return 'text-red-700';
      default: return 'text-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="bg-white border-slate-200 p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-slate-900 rounded-lg">
            <Settings className="size-5 text-white" />
          </div>
          <div>
            <h2 className="text-slate-900">관리자 패널</h2>
            <p className="text-slate-600 text-sm">CTF 사이트 크롤링 및 관리</p>
            <p className="text-slate-500 text-xs">선택된 대회: {competitionName}</p>
          </div>
        </div>

        {/* Status */}
        <div className="flex items-center gap-2">
          <span className="text-slate-600 text-sm">상태:</span>
          <Badge className={isRunning ? 'bg-green-100 text-green-700 border-green-200' : 'bg-slate-100 text-slate-700 border-slate-200'}>
            {isRunning ? '실행 중' : '중지됨'}
          </Badge>
          <span className="text-slate-600 text-sm ml-4">등록된 문제:</span>
          <Badge className="bg-blue-100 text-blue-700 border-blue-200">
            {currentProblems.length}개
          </Badge>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-6">
          {/* Control Panel */}
          <Card className="bg-white border-slate-200 p-6">
          <h3 className="text-slate-900 mb-4">크롤링 설정</h3>
          
          <div className="space-y-4">
            {/* URL Input */}
            <div className="space-y-2">
              <Label htmlFor="ctf-url" className="text-slate-700">
                CTF 사이트 URL
              </Label>
              <div className="relative">
                <LinkIcon className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-slate-400" />
                <Input
                  id="ctf-url"
                  type="url"
                  value={ctfUrl}
                  onChange={(e) => {
                    setCtfUrl(e.target.value);
                    if (settingsReady) setSettingsDirty(true);
                  }}
                  placeholder="https://ctf.example.com"
                  className="pl-10 border-slate-300"
                  disabled={isCrawling || isSettingsLoading}
                />
              </div>
              <p className="text-slate-500 text-sm">
                크롤링할 CTF 플랫폼의 URL을 입력하세요
              </p>
            </div>

            {/* Database Name Input */}
            <div className="space-y-2">
              <Label htmlFor="database-name" className="text-slate-700">
                데이터베이스 이름 설정
              </Label>
              <Input
                id="database-name"
                type="text"
                value={databaseName}
                onChange={(e) => {
                  setDatabaseName(e.target.value);
                  if (settingsReady) setSettingsDirty(true);
                }}
                placeholder="ctf_hunter_db"
                className="border-slate-300"
                disabled={isCrawling || isSettingsLoading}
              />
              <p className="text-slate-500 text-sm">
                크롤된 문제를 저장할 데이터베이스 스키마/컬렉션 이름을 입력하세요
              </p>
            </div>

            {/* API Key Input */}
            <div className="space-y-2">
              <Label htmlFor="api-key" className="text-slate-700">
                API Key (선택사항)
              </Label>
              <Input
                id="api-key"
                type="password"
                value={apiKey}
                onChange={(e) => {
                  setApiKey(e.target.value);
                  if (settingsReady) setSettingsDirty(true);
                }}
                placeholder="sk-********************************"
                className="border-slate-300"
                disabled={isCrawling || isSettingsLoading}
              />
              <p className="text-slate-500 text-sm">
                CTF 플랫폼이나 내부 API 연동이 필요하다면 키를 입력하세요
              </p>

              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
                <span>
                  {isSettingsLoading
                    ? '설정을 불러오는 중...'
                    : isSavingSettings
                      ? '설정을 저장하는 중...'
                      : settingsDirty
                        ? '변경 사항이 저장 대기 중입니다.'
                        : lastSavedAt
                          ? `마지막 저장: ${lastSavedAt.toLocaleTimeString('ko-KR')}`
                          : '자동 저장됨'}
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    saveSettings().catch(() => {});
                  }}
                  disabled={!settingsReady || isSettingsLoading || isSavingSettings}
                  className="border-slate-300 text-slate-700"
                >
                  설정 저장
                </Button>
              </div>
            </div>

            {/* Control Buttons */}
            <div className="space-y-2 pt-2">
              <div className="grid grid-cols-2 gap-2">
                <Button
                  onClick={handleStartCTF}
                  disabled={isCrawling || !ctfUrl.trim() || !databaseName.trim() || !apiKey.trim()}
                  className="w-full bg-slate-900 hover:bg-slate-800 text-white disabled:bg-slate-300"
                >
                  <Play className="size-4 mr-2" />
                  CTF 시작
                </Button>

                <Button
                  onClick={handleResetCTF}
                  disabled={isCrawling || !ctfUrl.trim() || !databaseName.trim() || !apiKey.trim()}
                  variant="outline"
                  className="border-red-300 text-red-700 hover:bg-red-50 disabled:opacity-50"
                >
                  <RotateCcw className="size-4 mr-2" />
                  CTF 갱신
                </Button>
              </div>

              <Button
                onClick={handleDeleteCompetition}
                disabled={isCrawling || isDeletingCompetition}
                variant="outline"
                className="border-red-400 text-red-700 hover:bg-red-50 disabled:opacity-50 w-full"
              >
                {isDeletingCompetition ? (
                  <>
                    <Loader2 className="size-4 mr-2 animate-spin" />
                    대회 삭제 중...
                  </>
                ) : (
                  <>
                    <Trash2 className="size-4 mr-2" />
                    CTF 삭제
                  </>
                )}
              </Button>
            </div>

            {/* Info */}
            <Alert className="bg-blue-50 border-blue-200">
              <AlertCircle className="size-4 text-blue-600" />
              <AlertDescription className="text-slate-700 text-sm">
                문제 데이터는 자동으로 로컬 DB와 파일 스토리지에 저장됩니다.
              </AlertDescription>
            </Alert>
          </div>
          </Card>

          {/* Manual Upload */}
          <Card className="bg-white border-slate-200 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-slate-900 rounded-lg">
                <FileJson className="size-5 text-white" />
              </div>
              <div>
                <h3 className="text-slate-900">문제 업로드</h3>
                <p className="text-slate-600 text-sm">JSON/ZIP 파일을 직접 등록합니다</p>
              </div>
            </div>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="manual-title" className="text-slate-700">
                  문제 이름
                </Label>
                <Input
                  id="manual-title"
                  type="text"
                  value={manualProblemTitle}
                  onChange={(event) => setManualProblemTitle(event.target.value)}
                  placeholder="예: SQL Injection Challenge"
                  className="border-slate-300"
                  disabled={isManualUploading}
                />
                <p className="text-xs text-slate-500">
                  비워두면 업로드한 파일 이름으로 자동 저장됩니다.
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="manual-description" className="text-slate-700">
                  문제 설명
                </Label>
                <Textarea
                  id="manual-description"
                  value={manualProblemDescription}
                  onChange={(event) => setManualProblemDescription(event.target.value)}
                  placeholder="문제 개요, 접속 정보, 플래그 포맷 등을 적어주세요."
                  className="border-slate-300 min-h-[120px]"
                  disabled={isManualUploading}
                />
                <p className="text-xs text-slate-500">
                  비워두면 기본 안내 문구가 저장됩니다.
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="manual-category" className="text-slate-700">
                  문제 분야
                </Label>
                <Select
                  value={manualCategory}
                  onValueChange={setManualCategory}
                  disabled={isManualUploading}
                >
                  <SelectTrigger id="manual-category" className="border-slate-300">
                    <SelectValue placeholder="분야 선택" />
                  </SelectTrigger>
                  <SelectContent>
                    {manualCategoryOptions.map(option => (
                      <SelectItem key={option} value={option}>
                        {option}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-slate-500">
                  업로드된 문제는 선택한 분야로 분류됩니다.
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="manual-file" className="text-slate-700">
                  문제 파일
                </Label>
                <Input
                  id="manual-file"
                  ref={manualFileInputRef}
                  type="file"
                  accept=".json,.zip,application/json,application/zip"
                  onChange={handleManualFileChange}
                  disabled={isManualUploading}
                  className="border-slate-300"
                />
                <p className="text-xs text-slate-500">
                  {manualFile
                    ? `${manualFile.name} (${formatFileSize(manualFile.size)})`
                    : '하나의 파일 또는 ZIP을 업로드하면 그대로 첨부됩니다. JSON/manifest를 포함하면 여러 문제를 한 번에 추가할 수 있습니다.'}
                </p>
                <p className="text-xs text-slate-500">
                  파일 없이 업로드하려면 문제 이름과 설명을 모두 입력하세요.
                </p>
              </div>

              <label className="flex items-center gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-slate-300"
                  checked={manualReplaceExisting}
                  onChange={(event) => setManualReplaceExisting(event.target.checked)}
                  disabled={isManualUploading}
                />
                기존 문제 삭제 후 업로드
              </label>

              <Button
                onClick={() => {
                  void handleManualUpload();
                }}
                disabled={
                  isManualUploading || (!manualFile && (
                    manualProblemTitle.trim().length === 0 || manualProblemDescription.trim().length === 0
                  ))
                }
                className="w-full"
              >
                {isManualUploading ? (
                  <>
                    <Loader2 className="size-4 mr-2 animate-spin" />
                    업로드 중...
                  </>
                ) : (
                  <>
                    <Upload className="size-4 mr-2" />
                    문제 업로드
                  </>
                )}
              </Button>

              <Alert className="bg-slate-50 border-slate-200">
                <AlertCircle className="size-4 text-slate-500" />
                <AlertDescription className="text-xs text-slate-600">
                  JSON/manifest가 없을 때는 단일 문제로 저장되며, ZIP은 자동으로 압축 해제되어 첨부파일로 등록됩니다. manifest를 포함하면 여러 문제를 한 번에 추가할 수 있습니다 (기본 업로드 한도 1GB).
                </AlertDescription>
              </Alert>
            </div>
          </Card>
        </div>

        {/* Crawl Logs */}
        <Card className="bg-white border-slate-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-slate-900">크롤링 로그</h3>
            <Button
              onClick={() => setCrawlLogs([])}
              variant="ghost"
              size="sm"
              className="text-slate-600 hover:text-slate-900"
            >
              로그 지우기
            </Button>
          </div>

          <ScrollArea className="h-[400px]">
            <div className="space-y-2 pr-4">
              {crawlLogs.length === 0 ? (
                <div className="text-center py-8 text-slate-500">
                  <p>크롤링 로그가 없습니다</p>
                  <p className="text-sm mt-1">CTF를 시작하면 로그가 표시됩니다</p>
                </div>
              ) : (
                crawlLogs.map((log, index) => (
                  <div
                    key={index}
                    className="flex items-start gap-3 p-3 bg-slate-50 rounded-lg border border-slate-200"
                  >
                    <div className="mt-0.5">
                      {getLogIcon(log.type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-sm ${getLogColor(log.type)}`}>
                        {log.message}
                      </p>
                      <p className="text-xs text-slate-500 mt-1">
                        {log.timestamp.toLocaleTimeString('ko-KR')}
                      </p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </Card>
      </div>

      {/* Quick Stats */}
      <Card className="bg-white border-slate-200 p-6">
        <h3 className="text-slate-900 mb-4">통계</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-slate-50 rounded-lg border border-slate-200">
            <div className="text-slate-900">{currentProblems.length}</div>
            <div className="text-slate-600 text-sm mt-1">총 문제</div>
          </div>
          <div className="text-center p-4 bg-green-50 rounded-lg border border-green-200">
            <div className="text-green-700">{currentProblems.filter(p => p.solved).length}</div>
            <div className="text-slate-600 text-sm mt-1">해결됨</div>
          </div>
          <div className="text-center p-4 bg-blue-50 rounded-lg border border-blue-200">
            <div className="text-blue-700">{currentProblems.filter(p => !p.solved).length}</div>
            <div className="text-slate-600 text-sm mt-1">미해결</div>
          </div>
          <div className="text-center p-4 bg-amber-50 rounded-lg border border-amber-200">
            <div className="text-amber-700">
              {currentProblems.reduce((sum, p) => sum + p.points, 0)}
            </div>
            <div className="text-slate-600 text-sm mt-1">총 점수</div>
          </div>
        </div>
      </Card>
    </div>
  );
}
