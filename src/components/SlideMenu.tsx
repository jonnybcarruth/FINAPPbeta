'use client';

import { useState } from 'react';
import { format } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useApp } from '@/context/AppContext';
import { useAuth } from '@/context/AuthContext';
import { setHapticsEnabled, hapticLight } from '@/lib/haptics';
import { useT, useFmt, useLocale, useCurrencySymbol } from '@/lib/i18n';
import BankAccounts from './BankAccounts';

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function SlideMenu({ open, onClose }: Props) {
  const { settings, setSettings, saveWithOverrides, projections } = useApp();
  const { user, signOut, deleteAccount } = useAuth();
  const t = useT();
  const fmt = useFmt();
  const sym = useCurrencySymbol();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;
  const [showLog, setShowLog] = useState(false);
  const [logFilter, setLogFilter] = useState<'all' | 'income' | 'expense'>('all');
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const toggleSetting = (field: 'darkMode' | 'hapticsEnabled' | 'soundsEnabled' | 'smartBudgetEnabled') => {
    void hapticLight();
    const currentVal = field === 'smartBudgetEnabled' ? settings.smartBudgetEnabled !== false : settings[field];
    const newVal = !currentVal;
    const newSettings = { ...settings, [field]: newVal };
    setSettings(newSettings);
    if (field === 'darkMode') {
      document.documentElement.classList.toggle('dark', newVal);
    }
    if (field === 'hapticsEnabled') {
      setHapticsEnabled(newVal);
    }
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
  };

  const setCurrency = (currency: 'USD' | 'BRL') => {
    void hapticLight();
    const newSettings = { ...settings, currency };
    setSettings(newSettings);
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
  };

  const setLanguage = (language: 'en' | 'pt') => {
    void hapticLight();
    const newSettings = { ...settings, language };
    setSettings(newSettings);
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
  };

  const updateProjection = <K extends 'startDate' | 'projectionMonths' | 'startingBalance'>(field: K, value: typeof settings[K]) => {
    const newSettings = { ...settings, [field]: value };
    setSettings(newSettings);
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
  };

  async function handleDeleteAccount() {
    const msg = settings.language === 'pt'
      ? 'Excluir permanentemente sua conta e todos os dados salvos? Isto não pode ser desfeito.'
      : 'Permanently delete your account and all saved data? This cannot be undone.';
    if (!confirm(msg)) return;
    setDeleting(true);
    setDeleteError(null);
    const { error } = await deleteAccount();
    setDeleting(false);
    if (error) setDeleteError(error);
  }

  const filtered = projections.filter((p) => {
    if (logFilter === 'income') return p.amount > 0;
    if (logFilter === 'expense') return p.amount < 0;
    return true;
  });

  const typeLabel = (tx: typeof projections[0]) => {
    if (tx.type === 'Savings') return t('savings');
    if (tx.type === 'Debt Payment') return t('debt');
    if (tx.type === 'One-Time') return tx.name.includes('(Planned)') ? t('plan') : t('add_transaction');
    return t('recurring');
  };

  if (showLog) {
    return (
      <>
        <div className={`fixed inset-0 bg-black/50 z-50 transition-opacity ${open ? 'opacity-100' : 'opacity-0 pointer-events-none'}`} onClick={() => { setShowLog(false); onClose(); }} />
        <div className={`fixed inset-y-0 right-0 w-full sm:w-[420px] bg-white dark:bg-gray-900 z-50 transform transition-transform duration-300 ${open ? 'translate-x-0' : 'translate-x-full'} flex flex-col`}>
          <div className="flex items-center justify-between p-4 border-b dd-border">
            <button onClick={() => setShowLog(false)} className="text-sm text-blue-600 font-medium">{t('back')}</button>
            <h2 className="text-base font-bold dd-text">{t('transaction_log')}</h2>
            <select value={logFilter} onChange={(e) => setLogFilter(e.target.value as typeof logFilter)}
              className="text-xs p-1.5 border rounded-lg dark:bg-gray-800 dark:text-white dark:border-gray-600">
              <option value="all">{t('all')}</option>
              <option value="income">{t('income_only')}</option>
              <option value="expense">{t('expense_only')}</option>
            </select>
          </div>
          <div className="flex-1 overflow-y-auto">
            {filtered.length === 0 && <p className="text-center text-gray-500 py-10">{t('no_transactions_day')}</p>}
            {filtered.map((p, i) => (
              <div key={i} className="flex justify-between items-center px-4 py-3 border-b border-gray-100 dark:border-gray-800">
                <div className="min-w-0 flex-1 mr-3">
                  <p className="text-sm font-medium dd-text truncate">{p.name}</p>
                  <p className="text-xs text-gray-500">{format(p.date, 'MMM d, yyyy', { locale: dateLocale })} · {typeLabel(p)}</p>
                </div>
                <p className={`text-sm font-semibold flex-shrink-0 ${p.amount >= 0 ? 'text-[var(--brand-neon)]' : 'text-[var(--negative)]'}`}>
                  {p.amount >= 0 ? '+' : ''}{fmt(p.amount)}
                </p>
              </div>
            ))}
          </div>
        </div>
      </>
    );
  }

  if (!open && !showLog) return null;

  return (
    <>
      <div
        className="fixed inset-0 z-50"
        style={{
          background: 'rgba(10,10,10,0.5)',
          animation: 'fadeIn 0.24s var(--ease) both',
        }}
        onClick={onClose}
      />
      <div
        className="fixed inset-y-0 right-0 w-80 max-w-full z-50 flex flex-col"
        style={{
          background: 'var(--surface)',
          boxShadow: 'var(--shadow-lg)',
          animation: 'slideInRight 0.3s cubic-bezier(0.32, 0.72, 0, 1) both',
        }}
      >
        <div className="flex items-center justify-between p-5 border-b dd-border">
          <h2 className="text-lg font-bold dd-text">{t('menu')}</h2>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-800">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {user && (
            <div className="p-5 border-b" style={{ borderColor: 'var(--line)' }}>
              <div className="dd-avatar" style={{ width: 48, height: 48, fontSize: 18, marginBottom: 12 }}>
                {(user.email?.[0] || 'U').toUpperCase()}
              </div>
              <p className="text-sm font-semibold" style={{ color: 'var(--fg-1)' }}>{user.email}</p>
              <p className="text-xs" style={{ color: 'var(--fg-3)', marginTop: 2 }}>{t('dindin_account')}</p>
            </div>
          )}

          {/* Projection Settings */}
          <div className="p-5 space-y-4 border-b dd-border">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{t('settings')}</p>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('starting_balance')} ({sym})</label>
              <input type="number" value={settings.startingBalance}
                onChange={(e) => updateProjection('startingBalance', parseFloat(e.target.value) || 0)}
                className="w-full p-2 text-sm border dd-border dark:bg-gray-800 dark:text-white rounded-lg" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('projection_start_date')}</label>
              <input type="date" value={settings.startDate}
                onChange={(e) => updateProjection('startDate', e.target.value)}
                className="w-full p-2 text-sm border dd-border dark:bg-gray-800 dark:text-white rounded-lg" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{t('projection_length')}</label>
              <select value={settings.projectionMonths}
                onChange={(e) => updateProjection('projectionMonths', parseInt(e.target.value))}
                className="w-full p-2 text-sm border dd-border dark:bg-gray-800 dark:text-white rounded-lg">
                <option value={3}>3 {t('months')}</option>
                <option value={6}>6 {t('months')}</option>
                <option value={12}>12 {t('months')}</option>
                <option value={24}>24 {t('months')}</option>
              </select>
            </div>
          </div>

          {/* Preferences */}
          <div className="p-5 space-y-4 border-b dd-border">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{t('preferences')}</p>

            <ToggleRow label={t('smart_budget')} checked={settings.smartBudgetEnabled !== false} onChange={() => toggleSetting('smartBudgetEnabled')} id="menu-smart" />
            <ToggleRow label={t('dark_mode')} checked={settings.darkMode} onChange={() => toggleSetting('darkMode')} id="menu-dark" />
            <ToggleRow label={t('vibrations')} checked={settings.hapticsEnabled} onChange={() => toggleSetting('hapticsEnabled')} id="menu-haptics" />
            <ToggleRow label={t('sounds')} checked={settings.soundsEnabled} onChange={() => toggleSetting('soundsEnabled')} id="menu-sounds" />

            <div>
              <p className="text-sm font-medium dd-text-2 mb-2">{t('currency')}</p>
              <div className="flex bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
                <button onClick={() => setCurrency('USD')}
                  className={`flex-1 py-1.5 text-sm font-semibold rounded-md transition ${settings.currency === 'USD' ? 'dd-surface text-gray-900 dark:text-white shadow' : 'text-gray-500'}`}>
                  $ USD
                </button>
                <button onClick={() => setCurrency('BRL')}
                  className={`flex-1 py-1.5 text-sm font-semibold rounded-md transition ${settings.currency === 'BRL' ? 'dd-surface text-gray-900 dark:text-white shadow' : 'text-gray-500'}`}>
                  R$ BRL
                </button>
              </div>
            </div>

            <div>
              <p className="text-sm font-medium dd-text-2 mb-2">{t('language')}</p>
              <div className="flex bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
                <button onClick={() => setLanguage('en')}
                  className={`flex-1 py-1.5 text-sm font-semibold rounded-md transition ${settings.language === 'en' ? 'dd-surface text-gray-900 dark:text-white shadow' : 'text-gray-500'}`}>
                  English
                </button>
                <button onClick={() => setLanguage('pt')}
                  className={`flex-1 py-1.5 text-sm font-semibold rounded-md transition ${settings.language === 'pt' ? 'dd-surface text-gray-900 dark:text-white shadow' : 'text-gray-500'}`}>
                  Português
                </button>
              </div>
            </div>
          </div>

          <div className="p-5 space-y-1 border-b dd-border">
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Bank Accounts</p>
            <BankAccounts />
          </div>

          <div className="p-5 space-y-1 border-b dd-border">
            <button onClick={() => setShowLog(true)}
              className="w-full flex items-center space-x-3 p-3 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-left">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <line x1="9" y1="6" x2="20" y2="6"/><line x1="9" y1="12" x2="20" y2="12"/><line x1="9" y1="18" x2="20" y2="18"/>
                <circle cx="4" cy="6" r="1.5" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="4" cy="18" r="1.5" fill="currentColor" stroke="none"/>
              </svg>
              <span className="text-sm font-medium dd-text">{t('transaction_log')}</span>
            </button>
          </div>
        </div>

        <div className="p-5 border-t dd-border space-y-2">
          <button onClick={() => signOut()} className="w-full py-2.5 text-sm font-semibold dd-text-2 bg-gray-100 dark:bg-gray-800 rounded-xl hover:bg-gray-200 dark:hover:bg-gray-700">
            {t('sign_out')}
          </button>
          <button onClick={handleDeleteAccount} disabled={deleting}
            className="w-full py-2.5 text-sm font-semibold text-[var(--negative)] bg-[var(--negative-bg)] dark:bg-[var(--surface-2)] rounded-xl hover:bg-[var(--negative-bg)] dark:hover:bg-[var(--surface-2)] disabled:opacity-60">
            {deleting ? t('please_wait') : t('delete_account')}
          </button>
          {deleteError && <p className="text-xs text-red-500 text-center">{deleteError}</p>}
        </div>
      </div>
    </>
  );
}

function ToggleRow({ label, checked, onChange, id }: { label: string; checked: boolean; onChange: () => void; id: string }) {
  return (
    <div className="flex items-center justify-between">
      <label htmlFor={id} className="text-sm font-medium dd-text-2">{label}</label>
      <div className="relative inline-block w-12 h-7 select-none">
        <input type="checkbox" id={id} checked={checked} onChange={onChange}
          className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer" />
        <label htmlFor={id} className="toggle-label block overflow-hidden h-7 rounded-full bg-gray-300 cursor-pointer" />
      </div>
    </div>
  );
}
