'use client';

import { useState } from 'react';
import { TRANSACTION_CATEGORIES, type CategoryId } from '@/lib/categories';
import { useApp } from '@/context/AppContext';
import { hapticLight } from '@/lib/haptics';

interface Props {
  value?: CategoryId;
  onChange: (id: CategoryId) => void;
  filter?: 'income' | 'expense' | 'all';
}

const INCOME_IDS = new Set(['salary', 'other']);

export default function CategoryPicker({ value, onChange, filter = 'all' }: Props) {
  const { settings, setSettings, saveWithOverrides } = useApp();
  const lang = settings.language;
  const [adding, setAdding] = useState(false);
  const [newName, setNewName] = useState('');

  const customCats = settings.customCategories || [];

  const handleDeleteCustom = (id: string) => {
    void hapticLight();
    const updated = customCats.filter((c) => c.id !== id);
    const newSettings = { ...settings, customCategories: updated };
    setSettings(newSettings);
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
    if (value === id) onChange('other');
  };

  const builtInCats = TRANSACTION_CATEGORIES.filter((c) => {
    if (filter === 'income') return INCOME_IDS.has(c.id);
    if (filter === 'expense') return !INCOME_IDS.has(c.id) || c.id === 'other';
    return true;
  });
  const allCats = [...builtInCats, ...customCats];
  const isCustom = (id: string) => customCats.some((c) => c.id === id);

  const handleAddCustom = () => {
    if (!newName.trim()) return;
    void hapticLight();
    const id = `custom-${Date.now()}`;
    const newCat = { id, en: newName.trim(), pt: newName.trim() };
    const updated = [...customCats, newCat];
    const newSettings = { ...settings, customCategories: updated };
    setSettings(newSettings);
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
    onChange(id);
    setNewName('');
    setAdding(false);
  };

  return (
    <div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {allCats.map((c) => (
          <div key={c.id} style={{ display: 'inline-flex', alignItems: 'center', position: 'relative' }}>
            <button
              type="button"
              onClick={() => { void hapticLight(); onChange(c.id); }}
              style={{
                padding: isCustom(c.id) ? '5px 28px 5px 12px' : '5px 12px',
                fontSize: 12,
                fontWeight: 600,
                borderRadius: 'var(--radius-pill)',
                border: value === c.id ? '1.5px solid var(--fg-1)' : '1px solid var(--line)',
                background: value === c.id ? 'var(--fg-1)' : 'var(--surface)',
                color: value === c.id ? 'var(--surface)' : 'var(--fg-2)',
                cursor: 'pointer',
                fontFamily: 'var(--font-ui)',
                transition: 'all var(--dur-fast) var(--ease)',
              }}
            >
              {lang === 'pt' ? c.pt : c.en}
            </button>
            {isCustom(c.id) && (
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); handleDeleteCustom(c.id); }}
                style={{
                  position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)',
                  width: 16, height: 16, borderRadius: '50%',
                  background: 'var(--fg-4)', color: 'var(--surface)',
                  border: 'none', cursor: 'pointer',
                  fontSize: 10, lineHeight: 1,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}
              >
                ×
              </button>
            )}
          </div>
        ))}
        <button
          type="button"
          onClick={() => { void hapticLight(); setAdding(!adding); }}
          style={{
            padding: '5px 12px',
            fontSize: 12,
            fontWeight: 600,
            borderRadius: 'var(--radius-pill)',
            border: '1px dashed var(--line)',
            background: 'transparent',
            color: 'var(--fg-3)',
            cursor: 'pointer',
            fontFamily: 'var(--font-ui)',
          }}
        >
          + {lang === 'pt' ? 'Nova' : 'New'}
        </button>
      </div>
      {adding && (
        <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder={lang === 'pt' ? 'Nome da categoria' : 'Category name'}
            autoFocus
            onKeyDown={(e) => e.key === 'Enter' && handleAddCustom()}
            style={{
              flex: 1, padding: '6px 10px', fontSize: 12,
              border: '1px solid var(--line)', borderRadius: 'var(--radius)',
              background: 'var(--surface)', color: 'var(--fg-1)',
              fontFamily: 'var(--font-ui)', outline: 'none',
            }}
          />
          <button
            type="button"
            onClick={handleAddCustom}
            className="dd-btn-primary"
            style={{ padding: '6px 14px', fontSize: 12 }}
          >
            {lang === 'pt' ? 'Criar' : 'Create'}
          </button>
        </div>
      )}
    </div>
  );
}
