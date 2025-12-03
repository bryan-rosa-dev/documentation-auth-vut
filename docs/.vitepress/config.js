import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(
  defineConfig({
    title: 'Análisis de Autenticación JWT',
    description: 'Análisis técnico de estrategias de autenticación JWT con diagramas interactivos',
    base: '/documentacion-auth-vut/',

    themeConfig: {
      nav: [
        { text: 'Inicio', link: '/' },
        { text: 'Análisis', link: '/analisis' },
        { text: 'Comparativa', link: '/comparativa' },
        { text: 'Recomendación', link: '/recomendacion' }
      ],

      sidebar: [
        {
          text: 'Documentación',
          items: [
            { text: 'Inicio', link: '/' },
            { text: '📊 Análisis de Seguridad', link: '/analisis' },
            { text: '⚖️ Comparativa', link: '/comparativa' },
            { text: '✅ Recomendación', link: '/recomendacion' }
          ]
        }
      ],

      socialLinks: [
        { icon: 'github', link: 'https://github.com' }
      ],

      footer: {
        message: 'Documentación técnica de estrategias de autenticación',
        copyright: 'MIT License'
      }
    },

    // Configuración de Mermaid
    mermaid: {
      theme: 'base',
      themeVariables: {
        primaryColor: '#3b82f6',
        primaryTextColor: '#1e293b',
        primaryBorderColor: '#2563eb',
        lineColor: '#64748b',
        secondaryColor: '#f1f5f9',
        tertiaryColor: '#f8fafc'
      }
    }
  })
)
