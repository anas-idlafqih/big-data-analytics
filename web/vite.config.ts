import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, host: "127.0.0.1" },
  build: {
    rollupOptions: {
      output: {
        manualChunks: { motion: ["framer-motion"], graph: ["react-force-graph-2d"] },
      },
    },
  },
});
