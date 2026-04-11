import type { Metadata, Viewport } from 'next';
import './globals.css';
import { AppProvider } from '@/context/AppContext';
import { AuthProvider } from '@/context/AuthContext';
import AuthGate from '@/components/AuthGate';

export const metadata: Metadata = {
  title: 'DinDin',
  description: 'Personal Finance Planning',
  other: {
    'apple-mobile-web-app-capable': 'yes',
    'apple-mobile-web-app-status-bar-style': 'default',
    'apple-mobile-web-app-title': 'DinDin',
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="apple-touch-icon" href="/Dindin.png" />
      </head>
      <body className="antialiased">
        <AuthProvider>
          <AppProvider>
            <AuthGate>{children}</AuthGate>
          </AppProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
