// vite.config.ts
import { defineConfig } from "vite";
import tsConfigPaths from "vite-tsconfig-paths";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";

export default defineConfig(({ command, isPreview }) => {
  // `vite dev` inherits NODE_ENV from the shell. A stray NODE_ENV=production
  // (common in containers) makes the dev server load React's production build
  // without dead-code elimination, and the app crashes on first render.
  if (command === "serve" && !isPreview && process.env.NODE_ENV === "production") {
    console.warn(
      "[sealbox-web] Ignoring NODE_ENV=production for the dev server; using development.",
    );
    process.env.NODE_ENV = "development";
  }

  return {
    server: {
      port: 3000,
    },
    optimizeDeps: {
      // Only the keys route imports these. Without pre-bundling, the first
      // visit makes Vite re-optimize and force a full reload, which signs the
      // user out because the token is kept in memory only.
      include: ["date-fns", "date-fns/locale"],
    },
    plugins: [
      tsConfigPaths(),
      tanstackStart({ customViteReactPlugin: true }),
      viteReact(),
    ],
  };
});
