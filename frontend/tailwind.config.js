/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Dark cybersecurity theme
        primary: {
          50: '#e6f9ff',
          100: '#b3ecff',
          200: '#80dfff',
          300: '#4dd2ff',
          400: '#1ac5ff',
          500: '#00b8e6',
          600: '#0099cc',
          700: '#007ab3',
          800: '#005b99',
          900: '#003c80',
        },
        dark: {
          50: '#2a3150',
          100: '#252b45',
          200: '#1f243a',
          300: '#1a1f35',
          400: '#151a2e',
          500: '#101427',
          600: '#0d1120',
          700: '#0a0e1a',
          800: '#070b13',
          900: '#04070d',
        },
        success: {
          DEFAULT: '#00ff88',
          dark: '#00cc6a',
        },
        warning: {
          DEFAULT: '#ffaa00',
          dark: '#cc8800',
        },
        danger: {
          DEFAULT: '#ff3366',
          dark: '#cc2952',
        },
        critical: {
          DEFAULT: '#ff0044',
          dark: '#cc0036',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.3s ease-in',
        'slide-in': 'slideIn 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
