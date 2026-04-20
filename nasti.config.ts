import { defineConfig } from '@nasti-toolchain/nasti';

export default defineConfig({
  framework: 'react',
  server: {
    port: 5173,
    proxy: {
      // Proxy API calls to Zixiao Cloud Account's own backend (see ./server).
      '/api': { target: 'http://localhost:5180', changeOrigin: true },
      '/oauth': { target: 'http://localhost:5180', changeOrigin: true },
    },
  },
});
