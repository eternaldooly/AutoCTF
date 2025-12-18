import { useState, useMemo } from 'react';
import { CTFProblem } from '../App';
import { Card } from './ui/card';
import { Badge } from './ui/badge';
import { Input } from './ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { ScrollArea } from './ui/scroll-area';
import { Search, CheckCircle2, Circle } from 'lucide-react';

interface CTFProblemListProps {
  selectedProblem: CTFProblem | null;
  onSelectProblem: (problem: CTFProblem) => void;
  onToggleSolved: (problemId: string) => void;
  problems: CTFProblem[];
}

const STORAGE_KEYS = {
  search: 'ctf-hunter:problems:search',
  category: 'ctf-hunter:problems:category',
  difficulty: 'ctf-hunter:problems:difficulty',
};

const readFromStorage = (key: string, fallback: string) => {
  if (typeof window === 'undefined') return fallback;
  try {
    const stored = window.localStorage.getItem(key);
    return stored ?? fallback;
  } catch {
    return fallback;
  }
};

export function CTFProblemList({ selectedProblem, onSelectProblem, onToggleSolved, problems }: CTFProblemListProps) {
  const [searchQuery, setSearchQuery] = useState(() => readFromStorage(STORAGE_KEYS.search, ''));
  const [categoryFilter, setCategoryFilter] = useState(() => readFromStorage(STORAGE_KEYS.category, 'all'));
  const [difficultyFilter, setDifficultyFilter] = useState(() => readFromStorage(STORAGE_KEYS.difficulty, 'all'));

  const persistValue = (key: string, value: string) => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem(key, value);
    } catch {
      // ignore storage failures (e.g., Safari private mode)
    }
  };

  const sanitizeDescription = useMemo(() => {
    const stripMarkdown = (value: string) => {
      if (!value) return '';
      return value
        .replace(/!\[(.*?)\]\((.*?)\)/g, '$1') // images
        .replace(/\[(.*?)\]\((.*?)\)/g, '$1') // links
        .replace(/`([^`]+)`/g, '$1') // inline code
        .replace(/https?:\/\/\S+/g, '') // raw urls
        .replace(/\*\*(.*?)\*\*/g, '$1')
        .replace(/\*(.*?)\*/g, '$1')
        .replace(/__([^_]+)__|_([^_]+)_/g, '$1$2');
    };

    return (description: string) => {
      const stripped = stripMarkdown(description);
      const lines = stripped
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => line && !line.includes('[접속 정보]'));
      return lines.join(' ').replace(/\s+/g, ' ').trim();
    };
  }, []);

  const filteredProblems = useMemo(() => {
    const difficultyOrder: Record<string, number> = {
      Easy: 0,
      Medium: 1,
      Hard: 2,
    };

    return problems
      .filter(problem => {
        const normalizedCategory = problem.normalizedCategory ?? 'Misc';
        const matchesSearch = problem.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                             problem.description.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesCategory = categoryFilter === 'all' || normalizedCategory === categoryFilter;
        const matchesDifficulty = difficultyFilter === 'all' || problem.difficulty === difficultyFilter;
        
        return matchesSearch && matchesCategory && matchesDifficulty;
      })
      .slice()
      .sort((a, b) => {
        const solvedCompare = Number(a.solved) - Number(b.solved);
        if (solvedCompare !== 0) return solvedCompare;

        const difficultyCompare = (difficultyOrder[a.difficulty] ?? 99) - (difficultyOrder[b.difficulty] ?? 99);
        if (difficultyCompare !== 0) return difficultyCompare;

        return a.title.localeCompare(b.title, 'ko');
      });
  }, [searchQuery, categoryFilter, difficultyFilter, problems]);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Easy': return 'bg-green-500/10 text-green-400 border-green-500/20';
      case 'Medium': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      case 'Hard': return 'bg-red-500/10 text-red-400 border-red-500/20';
      default: return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    }
  };

  const getCategoryColor = (category: string) => {
    const colors: Record<string, string> = {
      'Pwnable': 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      'Web': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      'Forensics': 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      'Crypto': 'bg-orange-500/10 text-orange-400 border-orange-500/20',
      'Reversing': 'bg-pink-500/10 text-pink-400 border-pink-500/20',
      'Misc': 'bg-slate-500/10 text-slate-400 border-slate-500/20'
    };
    return colors[category] || 'bg-slate-500/10 text-slate-400 border-slate-500/20';
  };

  return (
    <Card className="bg-white border-slate-200 p-6">
      <div className="space-y-4">
        {/* Header */}
        <div>
          <h2 className="text-slate-900 mb-1">문제 목록</h2>
          <p className="text-slate-600 text-sm">
            총 {filteredProblems.length}개 문제
          </p>
        </div>

        {/* Filters */}
        <div className="space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-slate-400" />
            <Input
              placeholder="문제 검색..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                persistValue(STORAGE_KEYS.search, e.target.value);
              }}
              className="pl-10 bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Select
              value={categoryFilter}
              onValueChange={(value) => {
                setCategoryFilter(value);
                persistValue(STORAGE_KEYS.category, value);
              }}
            >
              <SelectTrigger className="bg-slate-50 border-slate-300 text-slate-900">
                <SelectValue placeholder="카테고리" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">모든 카테고리</SelectItem>
                <SelectItem value="Web">Web</SelectItem>
                <SelectItem value="Pwnable">Pwnable</SelectItem>
                <SelectItem value="Crypto">Crypto</SelectItem>
                <SelectItem value="Forensics">Forensics</SelectItem>
                <SelectItem value="Reversing">Reversing</SelectItem>
                <SelectItem value="Misc">Misc</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={difficultyFilter}
              onValueChange={(value) => {
                setDifficultyFilter(value);
                persistValue(STORAGE_KEYS.difficulty, value);
              }}
            >
              <SelectTrigger className="bg-slate-50 border-slate-300 text-slate-900">
                <SelectValue placeholder="난이도" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">모든 난이도</SelectItem>
                <SelectItem value="Easy">Easy</SelectItem>
                <SelectItem value="Medium">Medium</SelectItem>
                <SelectItem value="Hard">Hard</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Problem List */}
        <ScrollArea className="h-[600px] pr-4">
          <div className="space-y-3">
            {filteredProblems.map((problem) => (
              <Card
                key={problem.id}
                className={`p-4 cursor-pointer transition-all border ${
                  selectedProblem?.id === problem.id
                    ? 'bg-slate-900 border-slate-900'
                    : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                }`}
                onClick={() => onSelectProblem(problem)}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-start gap-2 flex-1">
                      <button
                        type="button"
                        aria-label={problem.solved ? '문제 해결 상태 해제' : '문제 해결로 표시'}
                        onClick={(event) => {
                          event.stopPropagation();
                          onToggleSolved(problem.id);
                        }}
                        className="mt-0.5 rounded-full focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-400"
                      >
                        {problem.solved ? (
                          <CheckCircle2 className={`size-5 shrink-0 ${selectedProblem?.id === problem.id ? 'text-green-400' : 'text-green-600'}`} />
                        ) : (
                          <Circle className={`size-5 shrink-0 ${selectedProblem?.id === problem.id ? 'text-slate-200' : 'text-slate-300'}`} />
                        )}
                      </button>
                      <h3 className={selectedProblem?.id === problem.id ? 'text-white' : 'text-slate-900'}>{problem.title}</h3>
                    </div>
                    <span className={`shrink-0 ${selectedProblem?.id === problem.id ? 'text-yellow-400' : 'text-amber-600'}`}>{problem.points}pts</span>
                  </div>

                  <p className={`text-sm line-clamp-2 ml-7 ${selectedProblem?.id === problem.id ? 'text-slate-300' : 'text-slate-600'}`}>
                    {sanitizeDescription(problem.description)}
                  </p>

                  <div className="flex flex-wrap items-center gap-2 ml-7">
                    <Badge className={getCategoryColor(problem.normalizedCategory ?? 'Misc')}>
                      {problem.category}
                    </Badge>
                    <Badge className={getDifficultyColor(problem.difficulty)}>
                      {problem.difficulty}
                    </Badge>
                    <Badge variant="outline" className={selectedProblem?.id === problem.id ? 'text-slate-300 border-slate-600' : 'text-slate-600 border-slate-300'}>
                      {problem.source}
                    </Badge>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </ScrollArea>
      </div>
    </Card>
  );
}
