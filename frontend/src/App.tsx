import { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Navbar } from '@/components/layout/Navbar';
import { Sidebar } from '@/components/layout/Sidebar';
import { HomePage } from '@/pages/HomePage';
import { AuditPage } from '@/pages/AuditPage';
import { ReportPage } from '@/pages/ReportPage';
import { TemplatePage } from '@/pages/TemplatePage';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';

function ScrollToTop() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior });
  }, [pathname]);
  return null;
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <ScrollToTop />
        <div className="min-h-screen bg-[#0A0B0D]">
          <Navbar />
          <div className="flex">
            <Sidebar />
            <main className="min-w-0 flex-1 px-4 py-8 sm:px-8">
              <Routes>
                <Route path="/" element={<HomePage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/report" element={<ReportPage />} />
                <Route path="/report/:reportId" element={<ReportPage />} />
                <Route path="/templates" element={<TemplatePage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </ErrorBoundary>
  );
}