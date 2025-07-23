import typescript from '@rollup/plugin-typescript';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import { terser } from 'rollup-plugin-terser';

const external = ['react', 'react-dom'];
const globals = {
  react: 'React',
  'react-dom': 'ReactDOM',
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
    },
    external,
    plugins: [
      nodeResolve({
        browser: true,
        preferBuiltins: false,
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: true,
        declarationDir: 'dist',
        rootDir: 'src',
      }),
    ],
  },
  
  // CommonJS build - FIXED: matching package.json
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.cjs.js', // ✅ Now matches package.json
      format: 'cjs',
      sourcemap: true,
      exports: 'named',
    },
    external,
    plugins: [
      nodeResolve({
        browser: true,
        preferBuiltins: false,
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
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
    },
    external,
    plugins: [
      nodeResolve({
        browser: true,
        preferBuiltins: false,
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
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
    },
    external,
    plugins: [
      nodeResolve({
        browser: true,
        preferBuiltins: false,
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
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
