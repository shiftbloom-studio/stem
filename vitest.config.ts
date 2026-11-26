import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: { "cloudflare:workers": resolve("test/cloudflare-workers.ts") } },
  test: { environment: "node", include: ["test/**/*.test.ts"], testTimeout: 20000 },
});
