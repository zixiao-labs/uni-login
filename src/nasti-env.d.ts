/// <reference types="@nasti-toolchain/nasti/client" />

declare module '*.css' {
  const css: string;
  export default css;
}

declare module '@heroui/styles/css';

interface ImportMetaEnv {
  readonly VITE_GITHUB_CLIENT_ID?: string;
  readonly VITE_MAIN_CONSOLE_URL?: string;
  readonly VITE_API_BASE_URL?: string;
  readonly PROD: boolean;
  readonly DEV: boolean;
  readonly MODE: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

interface ImportMetaEnv {
  readonly VITE_GITHUB_CLIENT_ID?: string;
  readonly VITE_MAIN_CONSOLE_URL?: string;
  readonly PROD: boolean;
  readonly DEV: boolean;
  readonly MODE: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
