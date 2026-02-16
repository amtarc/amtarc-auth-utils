import { defineConfig } from 'vitepress';

export default defineConfig({
  title: '@amtarc/auth-utils',
  description: 'Enterprise-grade authentication utilities for TypeScript',

  ignoreDeadLinks: true,

  themeConfig: {
    logo: '/logo.svg',

    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'API Reference', link: '/api/core' },
      {
        text: 'GitHub',
        link: 'https://github.com/amtarc/amtarc-auth-utils',
      },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'Introduction', link: '/guide/introduction' },
            { text: 'Installation', link: '/guide/installation' },
            { text: 'Quick Start', link: '/guide/quick-start' },
          ],
        },
        {
          text: 'Core Concepts',
          items: [
            { text: 'Session Management', link: '/guide/sessions' },
            { text: 'Authorization & RBAC', link: '/guide/authorization' },
            { text: 'Guards & Middleware', link: '/guide/guards' },
            { text: 'Cookies', link: '/guide/cookies' },
            { text: 'Error Handling', link: '/guide/errors' },
          ],
        },
        {
          text: 'Authorization',
          items: [
            { text: 'RBAC (Role-Based)', link: '/guide/authorization' },
            { text: 'ABAC (Attribute-Based)', link: '/guide/abac' },
            { text: 'Resource-Based Access', link: '/guide/resource-access' },
            {
              text: 'Authorization Guards',
              link: '/guide/authorization-guards',
            },
          ],
        },
        {
          text: 'Advanced Features',
          items: [
            { text: 'Security Features', link: '/guide/security' },
            { text: 'Storage & Integration', link: '/guide/storage' },
          ],
        },
      ],
      '/api/': [
        {
          text: 'API Reference',
          items: [{ text: 'Core Package', link: '/api/core' }],
        },
      ],
    },

    socialLinks: [
      {
        icon: 'github',
        link: 'https://github.com/amtarc/amtarc-auth-utils',
      },
    ],

    search: {
      provider: 'local',
    },
  },

  markdown: {
    theme: {
      light: 'github-light',
      dark: 'github-dark',
    },
  },
});
