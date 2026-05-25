window.tailwind = window.tailwind || {};
window.tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            sans: ['Inter', 'ui-sans-serif', 'system-ui'],
            serif: ['"Instrument Serif"', 'ui-serif', 'Georgia'],
            mono: ['"JetBrains Mono"', 'ui-monospace']
          },
          colors: {
            ink: '#0b1220',
            mist: '#f6f7fb',
            line: '#e6e9f2',
            brand: {
              50:  '#ecfdf7',
              100: '#d2f7e7',
              200: '#a8edd1',
              500: '#0fb47a',
              600: '#0a8f61',
              700: '#0a6b4b'
            },
            steel: {
              50: '#f7f9fc',
              100: '#eef2f8',
              200: '#dde4ee',
              500: '#5b6a82',
              700: '#2c3a52'
            }
          },
          boxShadow: {
            panel: '0 1px 0 rgba(15,23,42,0.04), 0 24px 60px -24px rgba(15,23,42,0.18)',
            ring:  '0 0 0 6px rgba(15,180,122,0.12)',
            soft:  '0 1px 2px rgba(15,23,42,0.06), 0 8px 24px -10px rgba(15,23,42,0.12)'
          },
          backgroundImage: {
            'mesh': 'radial-gradient(1200px 600px at 10% -10%, #e9fbf3 0%, transparent 60%), radial-gradient(900px 500px at 100% 0%, #e8efff 0%, transparent 55%), linear-gradient(180deg, #f6f7fb 0%, #f1f4fa 100%)',
            'brand-grad': 'linear-gradient(135deg, #0fb47a 0%, #0a6b4b 60%, #0b1220 130%)'
          }
        }
      }
    };

