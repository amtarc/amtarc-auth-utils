module.exports = [
  {
    name: '@amtarc/auth-utils (full)',
    path: 'packages/core/dist/index.js',
    limit: '20 KB',
    ignore: ['crypto', 'util', 'buffer', 'events', 'stream'],
  },
  {
    name: '@amtarc/auth-utils/session',
    path: 'packages/core/dist/session/index.js',
    limit: '5 KB',
    ignore: ['crypto', 'util'],
  },
  {
    name: '@amtarc/auth-utils/security',
    path: 'packages/core/dist/security/index.js',
    limit: '20 KB',
    ignore: ['crypto', 'util', 'buffer'],
  },
  {
    name: '@amtarc/auth-utils/security/csrf',
    path: 'packages/core/dist/security/csrf/index.js',
    limit: '6 KB',
    ignore: ['crypto', 'util'],
  },
  {
    name: '@amtarc/auth-utils/security/rate-limit',
    path: 'packages/core/dist/security/rate-limit/index.js',
    limit: '8 KB',
    ignore: ['util'],
  },
  {
    name: '@amtarc/auth-utils/security/encryption',
    path: 'packages/core/dist/security/encryption/index.js',
    limit: '6 KB',
    ignore: ['crypto', 'util'],
  },
  {
    name: '@amtarc/auth-utils/security/headers',
    path: 'packages/core/dist/security/headers/index.js',
    limit: '4 KB',
    ignore: [],
  },
];
