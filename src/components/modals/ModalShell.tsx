'use client';

interface ModalShellProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

export default function ModalShell({ open, onClose, title, children }: ModalShellProps) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-40 overflow-y-auto h-full w-full flex items-center justify-center z-50 backdrop-blur-sm"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="relative mx-auto p-8 border w-full max-w-md shadow-lg rounded-2xl bg-white dark:bg-gray-800">
        <h3 className="text-xl font-bold mb-6 text-gray-800 dark:text-gray-100">{title}</h3>
        {children}
      </div>
    </div>
  );
}
