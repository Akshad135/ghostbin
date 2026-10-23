import { BrowserRouter, Navigate, Route, Routes, useParams } from 'react-router-dom';
import { Toaster } from 'sonner';
import { ThemeProvider } from '@/components/ThemeProvider';
import { AuthProvider } from '@/lib/auth';
import { Navbar } from '@/components/Navbar';
import { Home } from '@/pages/Home';
import { NewPaste } from '@/pages/NewPaste';
import { EditPaste } from '@/pages/EditPaste';
import { ViewPaste } from '@/pages/ViewPaste';
import { ErrorState } from '@/components/ErrorState';

function ThemedToaster() {
  return (
    <Toaster
      position="bottom-center"
      duration={2200}
      toastOptions={{
        style: {
          background: 'hsl(var(--card))',
          color: 'hsl(var(--foreground))',
          border: '1px solid hsl(var(--border))',
        },
        classNames: {
          success: 'toast-success',
          error: 'toast-error',
        },
      }}
    />
  );
}

function LegacyPasteRedirect() {
  const { id } = useParams<{ id: string }>();
  return <Navigate to={`/p/${encodeURIComponent(id ?? '')}`} replace />;
}

function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          <div className="h-[100dvh] flex flex-col overflow-hidden">
            <Navbar />
            <main className="flex-1 overflow-auto min-h-0">
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/new" element={<NewPaste />} />
                <Route path="/p/:id" element={<ViewPaste />} />
                <Route path="/paste/:id" element={<LegacyPasteRedirect />} />
                <Route path="/edit/:id" element={<EditPaste />} />
                <Route path="*" element={<ErrorState />} />
              </Routes>
            </main>
          </div>
          <ThemedToaster />
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}

export default App;
