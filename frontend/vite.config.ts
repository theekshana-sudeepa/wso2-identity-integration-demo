import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: process.env.GITHUB_PAGES === "true" ? "/wso2-identity-integration-demo/" : "/",
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true
  }
});
