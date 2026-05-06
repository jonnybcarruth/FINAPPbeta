'use client';

import { useState } from 'react';
import RecurringSchedulesView from './RecurringSchedulesView';
import DebtPlansView from './DebtPlansView';
import { useApp } from '@/context/AppContext';
import { useT, useCurrencySymbol } from '@/lib/i18n';
import { hapticLight, hapticSuccess } from '@/lib/haptics';
import { COMMON_BILL_TEMPLATES } from '@/lib/categories';
import { format } from 'date-fns';
import type { RecurringSchedule } from '@/lib/types';

type Segment = 'recurring' | 'debt';

export default function BillsView() {
  const { settings, recurringSchedules, setRecurringSchedules, saveWithOverrides } = useApp();
  const t = useT();
  const sym = useCurrencySymbol();
  const [segment, setSegment] = useState<Segment>('recurring');
  const [showTemplates, setShowTemplates] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<number | null>(null);
  const [templateAmount, setTemplateAmount] = useState('');

  const switchTo = (s: Segment) => {
    void hapticLight();
    setSegment(s);
  };

  const handleAddFromTemplate = () => {
    if (selectedTemplate === null || !templateAmount) return;
    const tmpl = COMMON_BILL_TEMPLATES[selectedTemplate];
    const name = settings.language === 'pt' ? tmpl.name_pt : tmpl.name_en;
    const newSchedule: RecurringSchedule = {
      id: `SCH-${Date.now()}`,
      name,
      amount: -parseFloat(templateAmount),
      startDate: format(new Date(), 'yyyy-MM-dd'),
      frequency: tmpl.frequency,
      dayValue: 1,
      enabled: true,
      category: tmpl.category,
    };
    const updated = [...recurringSchedules, newSchedule];
    setRecurringSchedules(updated);
    saveWithOverrides(updated, undefined, undefined, undefined, undefined);
    void hapticSuccess();
    setSelectedTemplate(null);
    setTemplateAmount('');
    setShowTemplates(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex bg-gray-100 dark:bg-gray-800 rounded-xl p-1">
        <button
          onClick={() => switchTo('recurring')}
          className={`flex-1 py-2 text-sm font-semibold rounded-lg transition ${
            segment === 'recurring'
              ? 'dd-surface text-gray-900 dark:text-white shadow'
              : 'text-gray-500'
          }`}
        >
          {t('recurring_schedules')}
        </button>
        <button
          onClick={() => switchTo('debt')}
          className={`flex-1 py-2 text-sm font-semibold rounded-lg transition ${
            segment === 'debt'
              ? 'dd-surface text-gray-900 dark:text-white shadow'
              : 'text-gray-500'
          }`}
        >
          {t('debt_plans')}
        </button>
      </div>

      {/* Quick-add templates */}
      {segment === 'recurring' && (
        <div className="dd-surface rounded-2xl shadow-sm overflow-hidden">
          <button
            onClick={() => { void hapticLight(); setShowTemplates(!showTemplates); }}
            className="w-full flex items-center justify-between p-4 text-left hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            <span className="text-sm font-semibold dd-text">
              ⚡ {settings.language === 'pt' ? 'Adicionar conta comum' : 'Quick-add common bill'}
            </span>
            <svg className={`w-4 h-4 text-gray-400 transition-transform ${showTemplates ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </button>
          {showTemplates && (
            <div className="p-4 pt-0 space-y-3">
              <div className="flex flex-wrap gap-2">
                {COMMON_BILL_TEMPLATES.map((tmpl, i) => {
                  const name = settings.language === 'pt' ? tmpl.name_pt : tmpl.name_en;
                  return (
                    <button
                      key={i}
                      onClick={() => { void hapticLight(); setSelectedTemplate(i); }}
                      className={`px-3 py-1.5 text-xs rounded-full font-medium transition ${
                        selectedTemplate === i
                          ? 'bg-ios-blue text-white'
                          : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                      }`}
                    >
                      {name}
                    </button>
                  );
                })}
              </div>
              {selectedTemplate !== null && (
                <div className="flex space-x-2 mt-2">
                  <div className="relative flex-1">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm">{sym}</span>
                    <input
                      type="number"
                      step="0.01"
                      placeholder="0.00"
                      value={templateAmount}
                      onChange={(e) => setTemplateAmount(e.target.value)}
                      className="w-full pl-8 pr-3 py-2 text-sm border dd-border dark:bg-gray-700 dark:text-white rounded-lg"
                    />
                  </div>
                  <button
                    onClick={handleAddFromTemplate}
                    disabled={!templateAmount}
                    className="px-4 py-2 bg-ios-blue text-white rounded-lg font-semibold text-sm disabled:opacity-40"
                  >
                    + {t('add')}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {segment === 'recurring' ? <RecurringSchedulesView /> : <DebtPlansView />}
    </div>
  );
}
