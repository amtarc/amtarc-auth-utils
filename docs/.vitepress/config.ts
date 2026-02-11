import { defineConfig } from 'vitepress';

export default defineConfig({
  title: 'amtarc-auth-utils',
  description: 'Enterprise-grade authentication utilities for TypeScript',

  ignoreDeadLinks: true,

  themeConfig: {
    logo: '/logo.svg',

    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'API Reference', link: '/api/' },
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
            { text: 'Guards & Middleware', link: '/guide/guards' },
            { text: 'Error Handling', link: '/guide/errors' },
          ],
        },
      ],
      '/api/': [
        {
          text: 'Packages',
          items: [
            { text: '@amtarc-auth-utils/core', link: '/api/core' },
            { text: '@amtarc-auth-utils/security', link: '/api/security' },
          ],
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
