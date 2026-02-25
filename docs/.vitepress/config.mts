import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'meshguard',
  description: 'Decentralized, serverless WireGuard mesh VPN daemon',
  base: '/meshguard/',
  head: [
    ['meta', { name: 'theme-color', content: '#00ff88' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.googleapis.com' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' }],
    ['link', { rel: 'stylesheet', href: 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap' }],
  ],
  themeConfig: {
    logo: undefined,
    siteTitle: 'meshguard',

    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Concepts', link: '/concepts/architecture' },
      { text: 'Reference', link: '/reference/cli' },
      { text: 'GitHub', link: 'https://github.com/igorls/meshguard' },
    ],

    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Trust Model', link: '/guide/trust-model' },
          { text: 'Configuration', link: '/guide/configuration' },
        ],
      },
      {
        text: 'Concepts',
        items: [
          { text: 'Architecture', link: '/concepts/architecture' },
          { text: 'Identity & Mesh IPs', link: '/concepts/identity-and-trust' },
          { text: 'SWIM Discovery', link: '/concepts/swim-discovery' },
          { text: 'WireGuard Integration', link: '/concepts/wireguard-integration' },
          { text: 'NAT Traversal', link: '/concepts/nat-traversal' },
          { text: 'Wire Protocol', link: '/concepts/wire-protocol' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'CLI Commands', link: '/reference/cli' },
          { text: 'Module Map', link: '/reference/modules' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/igorls/meshguard' },
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'meshguard contributors',
    },

    search: {
      provider: 'local',
    },

    outline: 'deep',
  },
})
