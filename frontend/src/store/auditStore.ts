import { create } from 'zustand';
import { AuditReport, ScanLog, ScanStatus, Vulnerability } from '@/types';
import { DEFAULT_CONTRACT } from '@/utils/highlight.utils';

export type EditorTab = 'paste' | 'upload';

interface AuditState {
  sourceCode: string;
  contractName: string;
  uploadFileName: string | null;
  uploadFileSize: number | null;
  editorTab: EditorTab;
  scanStatus: ScanStatus;
  scanProgress: number;
  scanLogs: ScanLog[];
  report: AuditReport | null;
  selectedVulnerability: Vulnerability | null;
  activeTab: string;
  errorMessage: string | null;
  verifyReport: AuditReport | null;
  verifyStatus: ScanStatus;

  setSourceCode: (code: string) => void;
  setContractName: (name: string) => void;
  setUploadFile: (fileName: string | null, fileSize: number | null) => void;
  setEditorTab: (tab: EditorTab) => void;
  setScanStatus: (status: ScanStatus) => void;
  updateProgress: (progress: number, message: string, stage?: string, data?: unknown) => void;
  addLog: (log: Omit<ScanLog, 'id' | 'timestamp'>) => void;
  setReport: (report: AuditReport | null) => void;
  selectVulnerability: (vuln: Vulnerability | null) => void;
  setActiveTab: (tab: string) => void;
  setError: (message: string | null) => void;
  resetScan: () => void;
  setVerifyReport: (report: AuditReport | null) => void;
  setVerifyStatus: (status: ScanStatus) => void;
}

let logCounter = 0;

export const useAuditStore = create<AuditState>((set) => ({
  sourceCode: DEFAULT_CONTRACT,
  contractName: 'VulnerableDeFiPool',
  uploadFileName: null,
  uploadFileSize: null,
  editorTab: 'paste',
  scanStatus: 'idle',
  scanProgress: 0,
  scanLogs: [],
  report: null,
  selectedVulnerability: null,
  activeTab: 'overview',
  errorMessage: null,
  verifyReport: null,
  verifyStatus: 'idle',

  setSourceCode: (code) => set({ sourceCode: code }),
  setContractName: (name) => set({ contractName: name }),
  setUploadFile: (fileName, fileSize) =>
    set({ uploadFileName: fileName, uploadFileSize: fileSize }),
  setEditorTab: (tab) => set({ editorTab: tab }),

  setScanStatus: (status) => set({ scanStatus: status }),

  updateProgress: (progress, message, stage, data) =>
    set((state) => ({
      scanProgress: progress,
      scanLogs: [
        ...state.scanLogs,
        {
          id: `log-${Date.now()}-${logCounter++}`,
          timestamp: new Date().toISOString(),
          stage: stage ?? state.activeTab,
          message,
          progress,
          data,
        },
      ],
    })),

  addLog: (log) =>
    set((state) => ({
      scanLogs: [
        ...state.scanLogs,
        {
          id: `log-${Date.now()}-${logCounter++}`,
          timestamp: new Date().toISOString(),
          ...log,
        },
      ],
    })),

  setReport: (report) => set({ report }),
  selectVulnerability: (vuln) => set({ selectedVulnerability: vuln }),

  setActiveTab: (tab) => set({ activeTab: tab }),

  setError: (message) => set({ errorMessage: message, scanStatus: 'error' }),

  resetScan: () =>
    set({
      scanStatus: 'idle',
      scanProgress: 0,
      scanLogs: [],
      report: null,
      selectedVulnerability: null,
      errorMessage: null,
    }),

  setVerifyReport: (report) => set({ verifyReport: report }),

  setVerifyStatus: (status) => set({ verifyStatus: status }),
}));