'use client';

import { useState } from 'react';
import RecurringSchedulesView from './RecurringSchedulesView';
import DebtPlansView from './DebtPlansView';
import { useT } from '@/lib/i18n';
import { hapticLight } from '@/lib/haptics';

type Segment = 'recurring' | 'debt';

export default function BillsView() {
  const t = useT();
  const [segment, setSegment] = useState<Segment>('recurring');

  const switchTo = (s: Segment) => {
    void hapticLight();
    setSegment(s);
  };

  return (
    <div className="space-y-4">
      <div className="flex bg-gray-100 dark:bg-gray-800 rounded-xl p-1">
        <button
          onClick={() => switchTo('recurring')}
          className={`flex-1 py-2 text-sm font-semibold rounded-lg transition ${
            segment === 'recurring'
              ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow'
              : 'text-gray-500'
          }`}
        >
          {t('recurring_schedules')}
        </button>
        <button
          onClick={() => switchTo('debt')}
          className={`flex-1 py-2 text-sm font-semibold rounded-lg transition ${
            segment === 'debt'
              ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow'
              : 'text-gray-500'
          }`}
        >
          {t('debt_plans')}
        </button>
      </div>

      {segment === 'recurring' ? <RecurringSchedulesView /> : <DebtPlansView />}
    </div>
  );
}
