---
layout: home

hero:
  name: "Análisis de Autenticación JWT"
  text: "Evaluación Técnica de Estrategias de Tokens"
  tagline: Análisis comparativo de seguridad entre HTTPOnly Cookies y manejo híbrido de tokens
  actions:
    - theme: brand
      text: Ver Análisis Completo
      link: /analisis
    - theme: alt
      text: Comparativa Técnica
      link: /comparativa

features:
  - icon: 🔒
    title: Seguridad Primero
    details: Análisis exhaustivo de vectores de ataque XSS, CSRF, y mejores prácticas de seguridad en autenticación moderna.

  - icon: 📊
    title: Comparativa Detallada
    details: Evaluación lado a lado de dos estrategias principales con diagramas de flujo interactivos y tablas comparativas.

  - icon: ⚡
    title: Implementación Práctica
    details: Ejemplos de código, flujos de autenticación y consideraciones de implementación para cada estrategia.

  - icon: 🎯
    title: Recomendación Basada en Datos
    details: Conclusiones técnicas con métricas de seguridad, complejidad de implementación y mantenibilidad.
---

## Contexto del Análisis

Este documento presenta un análisis técnico comparativo entre dos estrategias de autenticación JWT para aplicaciones web modernas:

### Estrategia 1: HTTPOnly Cookies para Ambos Tokens

Tanto el <span data-tooltip="Token de corta duración para acceso a recursos protegidos">Access Token (AT)</span> como el <span data-tooltip="Token de larga duración para renovar Access Tokens">Refresh Token (RT)</span> se almacenan en cookies HTTPOnly establecidas por el backend.

**Características principales:**
- ✅ Máxima protección contra XSS
- ✅ Gestión simplificada en el frontend
- ⚠️ Requiere protección CSRF robusta
- ⚠️ Mayor complejidad en entornos multi-dominio

### Estrategia 2: Manejo Híbrido (HTTPOnly RT + AT en Memoria)

El Refresh Token se almacena en cookie HTTPOnly, mientras el Access Token se maneja en memoria (variable en memoria).

**Características principales:**
- ✅ Balance entre seguridad y flexibilidad
- ✅ AT expira en 15 minutos (menor ventana de compromiso)
- ⚠️ Vulnerable a XSS durante la vida del AT
- ✅ Menor superficie de ataque CSRF

---

## Navegación Rápida

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin: 2rem 0;">
  <a href="./analisis" style="display: block; padding: 1.5rem; background: var(--vp-c-bg-soft); border-radius: 8px; text-decoration: none; border: 1px solid var(--vp-c-divider);">
    <h3 style="margin: 0 0 0.5rem 0;">📖 Análisis de Seguridad</h3>
    <p style="margin: 0; color: var(--vp-c-text-2); font-size: 0.9rem;">Diagramas de flujo y análisis de vectores de ataque</p>
  </a>

  <a href="./comparativa" style="display: block; padding: 1.5rem; background: var(--vp-c-bg-soft); border-radius: 8px; text-decoration: none; border: 1px solid var(--vp-c-divider);">
    <h3 style="margin: 0 0 0.5rem 0;">⚖️ Comparativa Técnica</h3>
    <p style="margin: 0; color: var(--vp-c-text-2); font-size: 0.9rem;">Tabla comparativa detallada de ventajas y desventajas</p>
  </a>

  <a href="./recomendacion" style="display: block; padding: 1.5rem; background: var(--vp-c-bg-soft); border-radius: 8px; text-decoration: none; border: 1px solid var(--vp-c-divider);">
    <h3 style="margin: 0 0 0.5rem 0;">✅ Recomendación Final</h3>
    <p style="margin: 0; color: var(--vp-c-text-2); font-size: 0.9rem;">Conclusión basada en criterios de seguridad y usabilidad</p>
  </a>
</div>

---

## Métricas de Decisión

| Criterio | Estrategia 1 (Dual HTTPOnly) | Estrategia 2 (Híbrido) |
|----------|------------------------------|------------------------|
| **Protección XSS** | <span class="security-badge high">Alta</span> | <span class="security-badge medium">Media</span> |
| **Protección CSRF** | <span class="security-badge medium">Media*</span> | <span class="security-badge high">Alta</span> |
| **Complejidad Frontend** | <span class="security-badge high">Baja</span> | <span class="security-badge medium">Media</span> |
| **Complejidad Backend** | <span class="security-badge medium">Media</span> | <span class="security-badge medium">Media</span> |
| **Soporte Multi-dominio** | <span class="security-badge low">Complejo</span> | <span class="security-badge high">Fácil</span> |

<small>* Requiere implementación de tokens CSRF o SameSite=Strict</small>
