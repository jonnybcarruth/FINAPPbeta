export const TRANSACTION_CATEGORIES = [
  { id: 'housing', en: 'Housing', pt: 'Moradia' },
  { id: 'groceries', en: 'Groceries', pt: 'Alimentação' },
  { id: 'transport', en: 'Transport', pt: 'Transporte' },
  { id: 'utilities', en: 'Utilities', pt: 'Contas' },
  { id: 'health', en: 'Health', pt: 'Saúde' },
  { id: 'entertainment', en: 'Entertainment', pt: 'Lazer' },
  { id: 'shopping', en: 'Shopping', pt: 'Compras' },
  { id: 'salary', en: 'Salary', pt: 'Salário' },
  { id: 'debt', en: 'Debt', pt: 'Dívida' },
  { id: 'savings', en: 'Savings', pt: 'Poupança' },
  { id: 'other', en: 'Other', pt: 'Outros' },
] as const;

export type CategoryId = string;

export interface CustomCategory {
  id: string;
  en: string;
  pt: string;
}

export const COMMON_BILL_TEMPLATES = [
  { name_en: 'Rent', name_pt: 'Aluguel', category: 'housing' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Electric', name_pt: 'Luz', category: 'utilities' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Water', name_pt: 'Água', category: 'utilities' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Internet', name_pt: 'Internet', category: 'utilities' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Phone', name_pt: 'Celular', category: 'utilities' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Car Payment', name_pt: 'Parcela Carro', category: 'transport' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Insurance', name_pt: 'Seguro', category: 'health' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Gym', name_pt: 'Academia', category: 'health' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Streaming', name_pt: 'Streaming', category: 'entertainment' as CategoryId, frequency: 'Monthly' as const },
  { name_en: 'Student Loan', name_pt: 'Empréstimo', category: 'debt' as CategoryId, frequency: 'Monthly' as const },
] as const;
