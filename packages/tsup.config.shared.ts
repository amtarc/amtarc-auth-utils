import { defineConfig } from 'tsup';

export function createTsupConfig(options = {}) {
  return defineConfig({
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: true,
    treeshake: true,
    target: 'es2022',
    minify: false,
    ...options,
  });
}
