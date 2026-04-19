'use client';

import { TRANSACTION_CATEGORIES, type CategoryId } from '@/lib/categories';
import { useApp } from '@/context/AppContext';

interface Props {
  value?: CategoryId;
  onChange: (id: CategoryId) => void;
  filter?: 'income' | 'expense' | 'all';
}

const INCOME_CATS = new Set<CategoryId>(['salary', 'freelance', 'investment', 'gift', 'other']);
const EXPENSE_CATS = new Set<CategoryId>(
  TRANSACTION_CATEGORIES.map(c => c.id).filter(id => !INCOME_CATS.has(id) || id === 'other') as CategoryId[]
);

export default function CategoryPicker({ value, onChange, filter = 'all' }: Props) {
  const { settings } = useApp();
  const lang = settings.language;

  const cats = TRANSACTION_CATEGORIES.filter((c) => {
    if (filter === 'income') return INCOME_CATS.has(c.id);
    if (filter === 'expense') return EXPENSE_CATS.has(c.id);
    return true;
  });

  return (
    <div className="flex flex-wrap gap-2">
      {cats.map((c) => (
        <button
          key={c.id}
          type="button"
          onClick={() => onChange(c.id)}
          className={`px-3 py-1.5 text-xs rounded-full font-medium transition ${
            value === c.id
              ? 'bg-ios-blue text-white shadow-sm'
              : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700'
          }`}
        >
          {c.icon} {lang === 'pt' ? c.pt : c.en}
        </button>
      ))}
    </div>
  );
}
