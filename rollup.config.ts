import typescript from '@rollup/plugin-typescript';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import { terser } from 'rollup-plugin-terser';

const external = ['react', 'react-dom'];
const globals = {
  react: 'React',
  'react-dom': 'ReactDOM',
};

const typescriptOptions = {
  tsconfig: './tsconfig.json',
  declaration: true,
  declarationDir: 'dist',
  rootDir: 'src',
  resolveJsonModule: true,
  preserveSymlinks: true,
};

const commonResolveOptions = {
  browser: true,
  preferBuiltins: false,
  exportConditions: ['node', 'import', 'module', 'default'],
};

export default [
  // ES Module build
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.esm.js',
      format: 'esm',
      sourcemap: true,
      exports: 'named',
      interop: 'auto',
    },
    external,
    plugins: [
      json(),
      nodeResolve(commonResolveOptions),
      commonjs({
        include: /node_modules/,
        transformMixedEsModules: true,
      }),
      typescript(typescriptOptions),
    ],
  },

  // CommonJS build
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.cjs.js',
      format: 'cjs',
      sourcemap: true,
      exports: 'named',
      interop: 'auto',
    },
    external,
    plugins: [
      json(),
      nodeResolve(commonResolveOptions),
      commonjs({
        include: /node_modules/,
        transformMixedEsModules: true,
      }),
      typescript({
        ...typescriptOptions,
        declaration: false, // Solo generar tipos una vez
      }),
    ],
  },

  // UMD build for browsers
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.umd.js',
      format: 'umd',
      name: 'AuthSDK',
      sourcemap: true,
      globals,
      exports: 'named',
      interop: 'auto',
    },
    external,
    plugins: [
      json(),
      nodeResolve(commonResolveOptions),
      commonjs({
        include: /node_modules/,
        transformMixedEsModules: true,
      }),
      typescript({
        ...typescriptOptions,
        declaration: false,
      }),
      terser({
        compress: {
          drop_console: false, // Keep console logs for debugging
          drop_debugger: true,
        },
        mangle: {
          keep_classnames: true, // Keep class names for better debugging
          keep_fnames: true,
        },
      }),
    ],
  },
  
  // ES Module build minified for production
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.esm.min.js',
      format: 'esm',
      sourcemap: true,
      exports: 'named',
      interop: 'auto',
    },
    external,
    plugins: [
      json(),
      nodeResolve(commonResolveOptions),
      commonjs({
        include: /node_modules/,
        transformMixedEsModules: true,
      }),
      typescript({
        ...typescriptOptions,
        declaration: false,
      }),
      terser({
        compress: {
          drop_console: true, // Remove console logs in production
          drop_debugger: true,
          pure_funcs: ['console.log', 'console.debug'],
        },
        mangle: {
          keep_classnames: true,
          keep_fnames: true,
        },
      }),
    ],
  },
];
