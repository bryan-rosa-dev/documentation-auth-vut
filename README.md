# Análisis de Autenticación JWT - Documentación Técnica

Análisis comparativo detallado entre dos estrategias de autenticación JWT para aplicaciones web modernas, con énfasis en ciberseguridad.

## 🚀 Estrategias Analizadas

### Estrategia 1: Dual HTTPOnly Cookies
Tanto Access Token como Refresh Token se almacenan en cookies HTTPOnly establecidas por el backend.

### Estrategia 2: Manejo Híbrido
Refresh Token en cookie HTTPOnly, Access Token en memoria del frontend (15 minutos de expiración).

## 📊 Contenido

- **Análisis de Seguridad**: Diagramas de flujo detallados con Mermaid
- **Comparativa Técnica**: Tabla exhaustiva de ventajas/desventajas
- **Vectores de Ataque**: Análisis de XSS, CSRF, y mitigaciones
- **Recomendación Final**: Guía de implementación paso a paso

## 🛠️ Tecnologías

- **VitePress**: Framework de documentación moderno
- **Mermaid**: Diagramas de flujo interactivos
- **GitHub Pages**: Hosting estático

## 📦 Instalación Local

```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/documentacion-auth-vut.git
cd documentacion-auth-vut

# Instalar dependencias
npm install

# Ejecutar servidor de desarrollo
npm run docs:dev

# Construir para producción
npm run docs:build

# Previsualizar build
npm run docs:preview
```

## 🌐 Ver Documentación

La documentación está desplegada en: **[https://tu-usuario.github.io/documentacion-auth-vut/](https://tu-usuario.github.io/documentacion-auth-vut/)**

## 📂 Estructura del Proyecto

```
documentacion-auth-vut/
├── docs/
│   ├── .vitepress/
│   │   ├── config.js          # Configuración VitePress
│   │   └── theme/
│   │       ├── index.js       # Theme personalizado
│   │       └── custom.css     # Estilos personalizados
│   ├── index.md               # Página principal
│   ├── analisis.md            # Análisis de seguridad con diagramas
│   ├── comparativa.md         # Tabla comparativa detallada
│   └── recomendacion.md       # Recomendación final e implementación
├── .github/
│   └── workflows/
│       └── deploy.yml         # GitHub Actions para deploy automático
├── package.json
└── README.md
```

## 🎯 Características

- ✅ Diagramas de flujo interactivos con Mermaid
- ✅ Análisis de vectores de ataque (XSS, CSRF)
- ✅ Código de ejemplo en JavaScript/Node.js
- ✅ Tablas comparativas con badges de seguridad
- ✅ Tooltips informativos
- ✅ Diseño responsive
- ✅ Modo oscuro/claro
- ✅ Deploy automático con GitHub Actions

## 📖 Secciones Principales

### 1. Introducción
Contexto y resumen ejecutivo de ambas estrategias.

### 2. Análisis de Seguridad
Diagramas de flujo completos para:
- Autenticación inicial
- Peticiones a recursos protegidos
- Renovación de tokens
- Logout

### 3. Comparativa Técnica
Tabla detallada comparando:
- Seguridad (XSS, CSRF, exposición de tokens)
- Implementación (complejidad, código)
- Arquitectura (multi-dominio, microservicios)
- Rendimiento (latencia, overhead)
- Mantenimiento (debugging, monitoreo)

### 4. Recomendación Final
Guía de implementación con:
- Plan paso a paso
- Código backend (Node.js/Express)
- Código frontend (React/Axios)
- Checklist de seguridad
- Métricas de éxito

## 🔐 Enfoque de Seguridad

El análisis hace énfasis especial en:

- **Protección XSS**: Comparativa de inmunidad vs ventana de 15 minutos
- **Protección CSRF**: Análisis de mitigaciones requeridas
- **Content Security Policy**: Configuraciones recomendadas
- **Sanitización de Inputs**: Ejemplos con DOMPurify
- **Headers de Seguridad**: Helmet.js y configuraciones
- **Token Rotation**: Estrategias de rotación de Refresh Tokens
- **Rate Limiting**: Protección contra fuerza bruta
- **Logging**: Monitoreo de eventos de seguridad

## 🚀 Despliegue en GitHub Pages

1. **Habilitar GitHub Pages** en tu repositorio:
   - Ve a Settings → Pages
   - Source: GitHub Actions

2. **Actualizar base en config**:
   ```javascript
   // docs/.vitepress/config.js
   export default defineConfig({
     base: '/documentacion-auth-vut/', // Tu nombre de repo
     // ...
   })
   ```

3. **Push a main**:
   ```bash
   git add .
   git commit -m "feat: initial documentation"
   git push origin main
   ```

4. **Verificar deploy**:
   - Ve a Actions tab
   - Espera a que termine el workflow
   - Accede a `https://tu-usuario.github.io/documentacion-auth-vut/`

## 🤝 Contribuir

Sugerencias y mejoras son bienvenidas:

1. Fork el repositorio
2. Crea una rama: `git checkout -b feature/mejora`
3. Commit cambios: `git commit -m 'feat: agregar análisis de OAuth'`
4. Push: `git push origin feature/mejora`
5. Abre un Pull Request


