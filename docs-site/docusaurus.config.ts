import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// ============================================================
// CONFIGURE THESE VALUES FOR YOUR PROJECT
// ============================================================
const PROJECT_TITLE = 'Reduit';
const PROJECT_TAGLINE = 'A sovereign, multi-user Proton Mail relay — use Proton from any IMAP/SMTP client, Apple Mail, and Claude Code';
const GITHUB_URL = 'https://gitea.stump.rocks/joestump/reduit';
const SITE_URL = 'https://joestump.pages.stump.rocks';
const BASE_URL = '/reduit/';
// ============================================================

const config: Config = {
  title: PROJECT_TITLE,
  tagline: PROJECT_TAGLINE,
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: SITE_URL,
  baseUrl: BASE_URL,

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

  markdown: {
    format: 'detect',
    mermaid: true,
  },

  themes: [
    '@docusaurus/theme-mermaid',
    [
      require.resolve('@easyops-cn/docusaurus-search-local'),
      {
        hashed: true,
        indexBlog: false,
        docsRouteBasePath: '/',
      },
    ],
  ],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          path: '../docs-generated',
          sidebarPath: './sidebars.ts',
          routeBasePath: '/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: PROJECT_TITLE,
      items: [
        {
          type: 'doc',
          docId: 'overview',
          position: 'left',
          label: '🗺️ Overview',
        },
        {
          type: 'docSidebar',
          sidebarId: 'guidesSidebar',
          position: 'left',
          label: '📖 Guides',
        },
        {
          type: 'docSidebar',
          sidebarId: 'specsSidebar',
          position: 'left',
          label: '📐 Specifications',
        },
        {
          type: 'docSidebar',
          sidebarId: 'decisionsSidebar',
          position: 'left',
          label: '📜 ADRs',
        },
        {
          href: GITHUB_URL,
          label: '🐙 Gitea',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Guides',
          items: [
            { label: 'Getting Started', to: '/guides/getting-started' },
            { label: 'Configuration', to: '/guides/configuration' },
            { label: 'Apple Mail', to: '/guides/apple-mail' },
            { label: 'Claude Code (MCP)', to: '/guides/claude-code' },
          ],
        },
        {
          title: 'Architecture',
          items: [
            { label: 'Specifications', to: '/specs' },
            { label: 'ADRs', to: '/decisions' },
          ],
        },
        {
          title: 'Project',
          items: [
            { label: 'Gitea', href: GITHUB_URL },
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} Joe Stump. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['go', 'bash', 'yaml', 'json', 'ini'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
