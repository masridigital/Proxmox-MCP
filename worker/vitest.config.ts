import { defineConfig } from "vitest/config";

// Plain Node environment: Node 22 provides WebCrypto (RSA, Ed25519), fetch, Request,
// Response and streams, which is everything the Worker code uses.
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
