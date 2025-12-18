import { useState } from 'react';
import type { Competition } from '../App';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Textarea } from './ui/textarea';
import { Label } from './ui/label';
import { Badge } from './ui/badge';
import { Loader2, Flag, PlusCircle, RefreshCw, Share2 } from 'lucide-react';
import { Switch } from './ui/switch';

interface CompetitionSelectorProps {
  competitions: Competition[];
  isLoading: boolean;
  onSelect: (competition: Competition) => void;
  onCreate: (payload: { name: string; description?: string; isShared?: boolean }) => Promise<void>;
  onRefresh: () => void;
}

export function CompetitionSelector({
  competitions,
  isLoading,
  onSelect,
  onCreate,
  onRefresh,
}: CompetitionSelectorProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [isShared, setIsShared] = useState(false);

  const handleCreate = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!name.trim()) {
      setFormError('대회 이름을 입력해주세요.');
      return;
    }

    setIsSubmitting(true);
    setFormError(null);
    try {
      await onCreate({ name: name.trim(), description: description.trim() || undefined, isShared });
      setName('');
      setDescription('');
      setIsShared(false);
    } catch (error) {
      setFormError(error instanceof Error ? error.message : '대회를 생성하지 못했습니다.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      <Card className="bg-white border-slate-200 p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-slate-900 rounded-lg">
              <Flag className="size-5 text-white" />
            </div>
            <div>
              <h1 className="text-slate-900">CTF 대회 선택</h1>
              <p className="text-slate-600 text-sm">대회를 선택하거나 새로운 대회를 생성하세요</p>
            </div>
          </div>
          <Button
            variant="outline"
            onClick={onRefresh}
            className="border-slate-300 text-slate-700"
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <Loader2 className="size-4 mr-2 animate-spin" />
                불러오는 중...
              </>
            ) : (
              <>
                <RefreshCw className="size-4 mr-2" />
                목록 새로고침
              </>
            )}
          </Button>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          {isLoading ? (
            <Card className="p-8 flex items-center justify-center border-slate-200">
              <Loader2 className="size-5 animate-spin text-slate-500" />
              <span className="ml-3 text-slate-600">대회 목록을 불러오는 중입니다...</span>
            </Card>
          ) : competitions.length === 0 ? (
            <Card className="p-8 border-dashed border-slate-300 text-center space-y-2">
              <p className="text-slate-700 font-medium">등록된 CTF 대회가 없습니다.</p>
              <p className="text-slate-500 text-sm">오른쪽에서 첫 번째 대회를 생성해보세요.</p>
            </Card>
          ) : (
            competitions.map(competition => (
              <Card
                key={competition.id}
                className="p-5 border-slate-200 hover:border-slate-400 transition-colors"
              >
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div>
                    <div className="flex items-center gap-3">
                      <h3 className="text-slate-900 text-lg font-semibold">{competition.name}</h3>
                      <Badge variant="secondary">
                        문제 {competition.problemCount}개
                      </Badge>
                      {competition.isShared && (
                        <Badge variant="outline" className="border-blue-500 text-blue-600">
                          공유 대회
                        </Badge>
                      )}
                    </div>
                    {competition.description && (
                      <p className="text-slate-600 text-sm mt-2">
                        {competition.description}
                      </p>
                    )}
                  </div>
                  <Button onClick={() => onSelect(competition)}>
                    이 대회 열기
                  </Button>
                </div>
              </Card>
            ))
          )}
        </div>

        <Card className="p-5 border-slate-200 h-fit">
          <div className="flex items-center gap-2 mb-4">
            <PlusCircle className="size-4 text-slate-600" />
            <h3 className="text-slate-900">새 CTF 대회 만들기</h3>
          </div>
          <form className="space-y-4" onSubmit={handleCreate}>
            <div className="space-y-2">
              <Label htmlFor="new-competition-name" className="text-slate-700">
                대회 이름
              </Label>
              <Input
                id="new-competition-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="예) AUTOCTF 2025"
                className="border-slate-300"
                disabled={isSubmitting}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="new-competition-description" className="text-slate-700">
                설명 (선택사항)
              </Label>
              <Textarea
                id="new-competition-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="대회의 특징이나 수집할 범위를 기록해 두세요"
                className="border-slate-300"
                rows={4}
                disabled={isSubmitting}
              />
            </div>

            <div className="flex items-center justify-between gap-3">
              <div className="space-y-1">
                <Label htmlFor="new-competition-shared" className="text-slate-700 flex items-center gap-1.5">
                  <Share2 className="size-3 text-slate-500" />
                  대회 공유
                </Label>
                <p className="text-xs text-slate-500">
                  켜면 다른 계정에서도 이 대회를 열어 같은 CLI와 문제를 함께 볼 수 있습니다.
                </p>
              </div>
              <Switch
                id="new-competition-shared"
                checked={isShared}
                onCheckedChange={(checked) => setIsShared(Boolean(checked))}
                disabled={isSubmitting}
              />
            </div>

            {formError && (
              <p className="text-sm text-red-600">{formError}</p>
            )}

            <Button
              type="submit"
              className="w-full bg-slate-900 hover:bg-slate-800"
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="size-4 mr-2 animate-spin" />
                  생성 중...
                </>
              ) : (
                <>
                  <PlusCircle className="size-4 mr-2" />
                  새 CTF 대회 생성
                </>
              )}
            </Button>
          </form>
        </Card>
      </div>
    </div>
  );
}
