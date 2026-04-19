'use client';

import type { ReactNode } from 'react';

interface Props {
  icon: ReactNode;
  title: string;
  description: string;
  cta?: { label: string; onClick: () => void };
  suggestions?: string[];
}

export default function EmptyState({ icon, title, description, cta, suggestions }: Props) {
  return (
    <div className="text-center py-10 px-4">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-50 dark:bg-blue-950 text-blue-600 dark:text-blue-300 mb-4">
        {icon}
      </div>
      <h3 className="text-lg font-bold text-gray-800 dark:text-gray-100 mb-2">{title}</h3>
      <p className="text-sm text-gray-500 dark:text-gray-400 max-w-sm mx-auto mb-5">{description}</p>
      {cta && (
        <button
          onClick={cta.onClick}
          className="px-5 py-2.5 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm"
        >
          {cta.label}
        </button>
      )}
      {suggestions && suggestions.length > 0 && (
        <div className="mt-6 flex flex-wrap gap-2 justify-center">
          {suggestions.map((s) => (
            <span key={s} className="text-xs px-3 py-1.5 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300">
              {s}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
