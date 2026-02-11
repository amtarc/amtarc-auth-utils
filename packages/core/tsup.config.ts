import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/session/index.ts',
    'src/guards/index.ts',
    'src/cookies/index.ts',
    'src/errors/index.ts',
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
