import { useApp } from '@/context/AppContext';

type Lang = 'en' | 'pt';
type Currency = 'USD' | 'BRL';

export const translations: Record<Lang, Record<string, string>> = {
  en: {
    // Nav / page titles
    calendar: 'Calendar',
    dashboard: 'Dashboard',
    debt: 'Debt',
    debt_plans: 'Debt Plans',
    schedules: 'Schedules',
    recurring: 'Recurring',
    plan: 'Plan',
    spending_plan: 'Spending Plan',
    savings: 'Savings',

    // Common buttons
    save: 'Save',
    cancel: 'Cancel',
    delete: 'Delete',
    edit: 'Edit',
    close: 'Close',
    add: 'Add',
    back: 'Back',
    please_wait: 'Please wait…',
    saved: 'Saved!',
    loading_data: 'Loading your data…',

    // Form labels
    name: 'Name',
    amount: 'Amount',
    date: 'Date',
    type: 'Type',
    frequency: 'Frequency',
    start_date: 'Start Date',
    end_date: 'End Date',
    optional: 'optional',
    day_of_week: 'Day of Week',
    day_of_month: 'Day of Month (1–31)',
    monthly: 'Monthly',
    weekly: 'Weekly',
    biweekly: 'Bi-Weekly',
    expense: 'Expense',
    income: 'Income',
    next_week: 'Next',
    prev_week: 'Previous',

    // Menu
    menu: 'Menu',
    preferences: 'Preferences',
    dark_mode: 'Dark Mode',
    vibrations: 'Vibrations',
    sounds: 'Sounds',
    currency: 'Currency',
    language: 'Language',
    transaction_log: 'Transaction Log',
    sign_out: 'Sign out',
    delete_account: 'Delete account',
    dindin_account: 'DinDin Account',

    // Calendar
    transaction_calendar: 'Transaction Calendar',
    add_event: 'Add Event',
    add_transaction: 'Add Transaction',
    edit_transaction: 'Edit Transaction',
    show_eod_balance: 'Show End of Day Balance',
    end_of_day_balance: 'End of Day Balance',
    no_transactions_day: 'No scheduled transactions for this day.',

    // Dashboard
    end_balance: 'End Balance',
    total_income: 'Total Income',
    total_expenses: 'Total Expenses',
    net_savings: 'Net Savings',
    total_saved: 'Total Saved',
    lowest_balance: 'Lowest Balance',
    avg_monthly_income: 'Avg Monthly Income',
    avg_monthly_expenses: 'Avg Monthly Expenses',
    cash_flow_projection: 'Cash Flow Projection',
    income_vs_expenses: 'Income vs Expenses',
    top_expenses: 'Top Expenses',
    net_monthly_flow: 'Net Monthly Flow',
    projected_negative_balance: 'Projected negative balance',
    projected_negative_desc: 'Your balance is projected to drop. Consider adjusting income or expenses.',

    // Recurring schedules
    recurring_schedules: 'Recurring Schedules',
    add_schedule: 'Add Schedule',
    new_recurring: 'Add Recurring Schedule',
    edit_recurring: 'Edit Recurring Schedule',
    manage_recurring: 'Manage long-term, repeating financial events. Toggle to enable/disable.',
    no_schedules: 'No schedules yet.',

    // Debt
    debt_plan_management: 'Debt Plan Management',
    add_debt_plan: 'Add Debt Plan',
    define_debt: 'Define structured debt repayments. Payments are calculated based on the payoff period.',
    no_debts: 'No debt plans yet.',
    months: 'months',
    per_month: '/mo',

    // Savings
    savings_plans: 'Savings Plans',
    add_savings: 'Add Savings',
    new_savings: 'New Savings Plan',
    edit_savings: 'Edit Savings Plan',
    savings_intro: 'Set up recurring contributions to your savings. These show as expenses in your cash flow and are tracked here.',
    no_savings: 'No savings plans yet. Start one to track your progress.',
    total_goal: 'Total Goal',
    overall_progress: 'Overall Progress',
    savings_goal: 'Savings Goal',
    goal: 'Goal',
    goal_desc: 'optional — track progress',
    amount_per_contribution: 'Amount per contribution',

    // Spending plan
    plan_period: 'Plan Period',
    projected_surplus: 'Projected Surplus Analysis',
    projected_savings: 'Projected Savings',
    available_weekly: 'Available Weekly',
    savings_target: 'Savings Target',
    commit_to_savings: 'Commit to Savings',
    spending_categories: 'Spending Categories',
    spending_plans: 'Spending Plans',
    select_plan: 'Select Plan',
    delete_plan: 'Delete Plan',
    aggressive: 'Aggressive Spending (100% Budget)',
    balanced: 'Balanced Spending (75% Budget)',
    conservative: 'Conservative Spending (50% Budget)',
    savings_exceeds: 'Savings goal exceeds surplus — no budget available.',
    weeks: 'weeks',
    per_week: '/week',

    // Settings panel
    settings: 'Settings',
    save_settings: 'Save Settings',
    projection_start_date: 'Projection Start Date',
    projection_length: 'Projection Length (Months)',
    starting_balance: 'Starting Balance',

    // Filters
    all: 'All',
    income_only: 'Income Only',
    expense_only: 'Expenses Only',
  },
  pt: {
    // Nav / page titles
    calendar: 'Calendário',
    dashboard: 'Painel',
    debt: 'Dívida',
    debt_plans: 'Planos de Dívida',
    schedules: 'Recorrentes',
    recurring: 'Recorrentes',
    plan: 'Plano',
    spending_plan: 'Plano de Gastos',
    savings: 'Poupança',

    // Common buttons
    save: 'Salvar',
    cancel: 'Cancelar',
    delete: 'Excluir',
    edit: 'Editar',
    close: 'Fechar',
    add: 'Adicionar',
    back: 'Voltar',
    please_wait: 'Aguarde…',
    saved: 'Salvo!',
    loading_data: 'Carregando seus dados…',

    // Form labels
    name: 'Nome',
    amount: 'Valor',
    date: 'Data',
    type: 'Tipo',
    frequency: 'Frequência',
    start_date: 'Data Inicial',
    end_date: 'Data Final',
    optional: 'opcional',
    day_of_week: 'Dia da Semana',
    day_of_month: 'Dia do Mês (1–31)',
    monthly: 'Mensal',
    weekly: 'Semanal',
    biweekly: 'Quinzenal',
    expense: 'Despesa',
    income: 'Receita',
    next_week: 'Próximo',
    prev_week: 'Anterior',

    // Menu
    menu: 'Menu',
    preferences: 'Preferências',
    dark_mode: 'Modo Escuro',
    vibrations: 'Vibrações',
    sounds: 'Sons',
    currency: 'Moeda',
    language: 'Idioma',
    transaction_log: 'Histórico de Transações',
    sign_out: 'Sair',
    delete_account: 'Excluir conta',
    dindin_account: 'Conta DinDin',

    // Calendar
    transaction_calendar: 'Calendário de Transações',
    add_event: 'Adicionar',
    add_transaction: 'Adicionar Transação',
    edit_transaction: 'Editar Transação',
    show_eod_balance: 'Mostrar Saldo Final do Dia',
    end_of_day_balance: 'Saldo Final do Dia',
    no_transactions_day: 'Nenhuma transação agendada para este dia.',

    // Dashboard
    end_balance: 'Saldo Final',
    total_income: 'Receita Total',
    total_expenses: 'Despesas Totais',
    net_savings: 'Poupança Líquida',
    total_saved: 'Total Poupado',
    lowest_balance: 'Menor Saldo',
    avg_monthly_income: 'Receita Média Mensal',
    avg_monthly_expenses: 'Despesa Média Mensal',
    cash_flow_projection: 'Projeção de Fluxo de Caixa',
    income_vs_expenses: 'Receitas vs Despesas',
    top_expenses: 'Maiores Despesas',
    net_monthly_flow: 'Fluxo Mensal Líquido',
    projected_negative_balance: 'Saldo negativo previsto',
    projected_negative_desc: 'Seu saldo deve ficar negativo. Ajuste suas receitas ou despesas.',

    // Recurring schedules
    recurring_schedules: 'Agendamentos Recorrentes',
    add_schedule: 'Adicionar',
    new_recurring: 'Novo Agendamento Recorrente',
    edit_recurring: 'Editar Agendamento Recorrente',
    manage_recurring: 'Gerencie eventos financeiros repetidos. Alterne para ativar/desativar.',
    no_schedules: 'Nenhum agendamento ainda.',

    // Debt
    debt_plan_management: 'Gerenciar Planos de Dívida',
    add_debt_plan: 'Adicionar Dívida',
    define_debt: 'Defina pagamentos estruturados de dívidas. Os pagamentos são calculados com base no prazo.',
    no_debts: 'Nenhum plano de dívida ainda.',
    months: 'meses',
    per_month: '/mês',

    // Savings
    savings_plans: 'Planos de Poupança',
    add_savings: 'Adicionar',
    new_savings: 'Novo Plano de Poupança',
    edit_savings: 'Editar Plano de Poupança',
    savings_intro: 'Configure contribuições recorrentes para sua poupança. Elas aparecem como despesas no fluxo de caixa e são rastreadas aqui.',
    no_savings: 'Nenhum plano de poupança ainda. Crie um para acompanhar seu progresso.',
    total_goal: 'Meta Total',
    overall_progress: 'Progresso Geral',
    savings_goal: 'Meta de Poupança',
    goal: 'Meta',
    goal_desc: 'opcional — acompanhe o progresso',
    amount_per_contribution: 'Valor por contribuição',

    // Spending plan
    plan_period: 'Período do Plano',
    projected_surplus: 'Análise de Excedente Projetado',
    projected_savings: 'Poupança Projetada',
    available_weekly: 'Disponível Semanalmente',
    savings_target: 'Meta de Poupança',
    commit_to_savings: 'Compromisso de Poupança',
    spending_categories: 'Categorias de Gastos',
    spending_plans: 'Planos de Gastos',
    select_plan: 'Selecionar Plano',
    delete_plan: 'Excluir Plano',
    aggressive: 'Gasto Agressivo (100% do Orçamento)',
    balanced: 'Gasto Equilibrado (75% do Orçamento)',
    conservative: 'Gasto Conservador (50% do Orçamento)',
    savings_exceeds: 'A meta de poupança excede o excedente — sem orçamento disponível.',
    weeks: 'semanas',
    per_week: '/semana',

    // Settings panel
    settings: 'Configurações',
    save_settings: 'Salvar Configurações',
    projection_start_date: 'Data Inicial da Projeção',
    projection_length: 'Duração da Projeção (Meses)',
    starting_balance: 'Saldo Inicial',

    // Filters
    all: 'Todos',
    income_only: 'Só Receitas',
    expense_only: 'Só Despesas',
  },
};

export function useT() {
  const { settings } = useApp();
  return (key: string): string => translations[settings.language]?.[key] ?? translations.en[key] ?? key;
}

export function useFmt() {
  const { settings } = useApp();
  const locale = settings.currency === 'BRL' ? 'pt-BR' : 'en-US';
  return (amount: number): string =>
    amount.toLocaleString(locale, { style: 'currency', currency: settings.currency });
}

export function useLocale() {
  const { settings } = useApp();
  return settings.language === 'pt' ? 'pt-BR' : 'en-US';
}

export function useCurrencySymbol() {
  const { settings } = useApp();
  return settings.currency === 'BRL' ? 'R$' : '$';
}
