// Vite "?raw" imports (used to inspect wrangler.jsonc without Node type definitions).
declare module "*?raw" {
  const content: string;
  export default content;
}
