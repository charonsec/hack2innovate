/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        background: '#0A0B0D',
        surface: '#111318',
        surface2: '#1A1D25',
        border: '#2A2D35',
        primary: '#00FF88',
        secondary: '#0EA5E9',
        accent: '#8B5CF6',
        critical: '#EF4444',
        high: '#F97316',
        medium: '#EAB308',
        low: '#3B82F6',
        info: '#6B7280',
        textPrimary: '#F1F5F9',
        textSecondary: '#94A3B8',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      borderColor: {
        DEFAULT: '#2A2D35',
      },
      boxShadow: {
        glow: '0 0 20px rgba(0,255,136,0.15)',
        'glow-strong': '0 0 40px rgba(0,255,136,0.35)',
      },
      backgroundImage: {
        'gradient-main': 'linear-gradient(135deg, #00FF88 0%, #0EA5E9 100%)',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'scan-cursor': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        'matrix-fall': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 0.4s ease-in-out',
        'scan-cursor': 'scan-cursor 1s step-end infinite',
        'matrix-fall': 'matrix-fall 12s linear infinite',
      },
    },
  },
  plugins: [],
};