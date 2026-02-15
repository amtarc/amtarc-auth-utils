import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/session/index.ts',
    'src/guards/index.ts',
    'src/cookies/index.ts',
    'src/errors/index.ts',
    'src/storage/index.ts',
    'src/security/index.ts',
    'src/security/csrf/index.ts',
    'src/security/rate-limit/index.ts',
    'src/security/headers/index.ts',
    'src/security/encryption/index.ts',
    'src/authorization/index.ts',
    'src/authorization/rbac/index.ts',
    'src/authorization/types.ts',
  ],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: true,
  treeshake: true,
  minify: false,
  target: 'es2022',
  outDir: 'dist',
});
