/// <reference types="vite/client" />

interface MonacoEnvironment {
  getWorker?(moduleId: string, label: string): Worker;
  getWorkerUrl?(moduleId: string, label: string): string;
}

interface Window {
  MonacoEnvironment?: MonacoEnvironment;
}

declare var MonacoEnvironment: MonacoEnvironment | undefined;
