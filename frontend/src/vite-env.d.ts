/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_WSO2_BASE_URL?: string;
  readonly VITE_CLIENT_ID?: string;
  readonly VITE_REDIRECT_URI?: string;
  readonly VITE_BACKEND_API_URL?: string;
  readonly VITE_SCOPE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
