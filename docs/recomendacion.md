# Recomendación Final

## Resumen Ejecutivo para Tomadores de Decisión

<div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 2rem; border-radius: 12px; margin: 2rem 0;">
  <h2 style="margin-top: 0; color: white;">🎯 Recomendación Principal</h2>
  <h3 style="color: white;">Para la mayoría de aplicaciones web modernas: Estrategia 2 (Híbrido)</h3>
  <p style="font-size: 1.1rem; margin-bottom: 0;">
    <strong>Con la condición obligatoria</strong> de implementar Content Security Policy estricta y sanitización de inputs.
    Si tu equipo no puede garantizar mitigación XSS robusta, opta por Estrategia 1.
  </p>
</div>

---

## Justificación Técnica

### Por qué Estrategia 2 es Superior en 2025

1. **Ecosistema Web Moderno**
   - Frameworks (React, Vue, Angular) sanitizan automáticamente
   - CSP es estándar en navegadores modernos
   - Herramientas de auditoría (ESLint, Snyk) detectan XSS

2. **Arquitecturas Actuales**
   - Microservicios son la norma
   - Multi-dominio (app.com, api.com) es común
   - Mobile + Web requieren portabilidad de tokens

3. **Performance y Escalabilidad**
   - CDNs son críticos para UX global
   - Cookies dificultan caching
   - AT en header permite mejor distribución

4. **Ventana de Compromiso Aceptable**
   - 15 minutos es suficientemente corto
   - RT permanece protegido en HTTPOnly
   - Incluso con XSS, daño es limitado

---

## Plan de Implementación Recomendado

### Fase 1: Fundamentos 

<div class="info-box">

#### Backend: Endpoints de Autenticación

```javascript
// auth.controller.js
import jwt from 'jsonwebtoken';
import { hash, compare } from 'bcrypt';

export const login = async (req, res) => {
  const { email, password } = req.body;

  // 1. Validar credenciales
  const user = await User.findOne({ email });
  if (!user || !(await compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  // 2. Generar tokens
  const accessToken = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId: user.id, tokenVersion: user.tokenVersion },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );

  // 3. Almacenar RT en DB
  await RefreshToken.create({
    userId: user.id,
    token: refreshToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  });

  // 4. Establecer cookie HTTPOnly para RT
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS only en prod
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/auth/refresh'
  });

  // 5. Retornar AT en body
  res.json({
    accessToken,
    expiresIn: 900, // 15 minutos en segundos
    user: {
      id: user.id,
      email: user.email,
      name: user.name
    }
  });
};

export const refresh = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token no proporcionado' });
  }

  try {
    // 1. Verificar token
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    // 2. Validar en DB (no revocado)
    const tokenExists = await RefreshToken.findOne({
      userId: payload.userId,
      token: refreshToken,
      expiresAt: { $gt: new Date() }
    });

    if (!tokenExists) {
      return res.status(401).json({ error: 'Refresh token inválido o revocado' });
    }

    // 3. Verificar token version (permite invalidar todos los tokens del usuario)
    const user = await User.findById(payload.userId);
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ error: 'Token version inválida' });
    }

    // 4. Generar nuevo AT
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '15m' }
    );

    // 5. (Opcional) Rotar RT para mayor seguridad
    const newRefreshToken = jwt.sign(
      { userId: user.id, tokenVersion: user.tokenVersion },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // Eliminar RT viejo
    await RefreshToken.deleteOne({ token: refreshToken });

    // Crear RT nuevo
    await RefreshToken.create({
      userId: user.id,
      token: newRefreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    // Establecer nuevo RT en cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/auth/refresh'
    });

    res.json({
      accessToken,
      expiresIn: 900
    });
  } catch (error) {
    return res.status(401).json({ error: 'Refresh token inválido' });
  }
};

export const logout = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (refreshToken) {
    // Eliminar RT de DB
    await RefreshToken.deleteOne({ token: refreshToken });
  }

  // Clear cookie
  res.clearCookie('refreshToken', { path: '/auth/refresh' });
  res.json({ message: 'Logout exitoso' });
};
```

#### Middleware de Autenticación

```javascript
// auth.middleware.js
import jwt from 'jsonwebtoken';

export const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access token no proporcionado' });
  }

  const token = authHeader.substring(7); // Remover "Bearer "

  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = payload; // Adjuntar datos del usuario al request
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Access token inválido o expirado' });
  }
};
```

</div>

### Fase 2: Frontend 

<div class="info-box">

#### Servicio de Autenticación

```javascript
// authService.js
class AuthService {
  #accessToken = null;
  #expiresAt = null;

  setToken(token, expiresIn) {
    this.#accessToken = token;
    this.#expiresAt = Date.now() + (expiresIn * 1000);

    // Opcional: Programar refresh automático 1 minuto antes de expiración
    this.#scheduleTokenRefresh(expiresIn - 60);
  }

  getToken() {
    if (!this.#accessToken || Date.now() >= this.#expiresAt) {
      return null;
    }
    return this.#accessToken;
  }

  clearToken() {
    this.#accessToken = null;
    this.#expiresAt = null;
  }

  isTokenExpired() {
    return !this.#accessToken || Date.now() >= this.#expiresAt;
  }

  async login(email, password) {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
      credentials: 'include' // Importante: Enviar/recibir cookies
    });

    if (!response.ok) {
      throw new Error('Login fallido');
    }

    const data = await response.json();
    this.setToken(data.accessToken, data.expiresIn);

    return data.user;
  }

  async refresh() {
    const response = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include' // Envía cookie refreshToken
    });

    if (!response.ok) {
      this.clearToken();
      throw new Error('Refresh fallido');
    }

    const data = await response.json();
    this.setToken(data.accessToken, data.expiresIn);

    return data.accessToken;
  }

  async logout() {
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });

    this.clearToken();
  }

  #scheduleTokenRefresh(delaySeconds) {
    if (delaySeconds > 0) {
      setTimeout(() => {
        this.refresh().catch(() => {
          // Refresh falló, redirigir a login
          window.location.href = '/login';
        });
      }, delaySeconds * 1000);
    }
  }
}

export const authService = new AuthService();
```

#### HTTP Client con Interceptores (Axios)

```javascript
// httpClient.js
import axios from 'axios';
import { authService } from './authService';

const httpClient = axios.create({
  baseURL: '/api',
  withCredentials: true // Importante: Enviar cookies
});

// Request interceptor: Agregar AT a cada petición
httpClient.interceptors.request.use(
  (config) => {
    const token = authService.getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: Manejar 401 y refresh automático
httpClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Si es 401 y no es un retry
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Intentar refresh
        const newToken = await authService.refresh();

        // Actualizar header con nuevo token
        originalRequest.headers.Authorization = `Bearer ${newToken}`;

        // Reintentar request original
        return httpClient(originalRequest);
      } catch (refreshError) {
        // Refresh falló, redirigir a login
        authService.clearToken();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default httpClient;
```

#### Componente de Login (React)

```jsx
// Login.jsx
import React, { useState } from 'react';
import { authService } from '../services/authService';
import { useNavigate } from 'react-router-dom';

export const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await authService.login(email, password);
      navigate('/dashboard');
    } catch (err) {
      setError('Credenciales inválidas');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
        required
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
        required
      />
      {error && <div className="error">{error}</div>}
      <button type="submit" disabled={loading}>
        {loading ? 'Cargando...' : 'Iniciar Sesión'}
      </button>
    </form>
  );
};
```

</div>

### Fase 3: Seguridad 

<div class="info-box danger">

#### Content Security Policy (CRÍTICO)

```javascript
// Middleware en Express
import helmet from 'helmet';

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"], // NO permitir 'unsafe-inline' o 'unsafe-eval'
      styleSrc: ["'self'", "'unsafe-inline'"], // Solo si es necesario
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.ejemplo.com"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  })
);
```

#### Sanitización de Inputs

```javascript
// Usar DOMPurify en frontend
import DOMPurify from 'dompurify';

const sanitizeUserInput = (html) => {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
  });
};

// React: Evitar dangerouslySetInnerHTML
// ❌ NO HACER:
<div dangerouslySetInnerHTML={{__html: userContent}} />

// ✅ HACER:
<div>{sanitizeUserInput(userContent)}</div>
```

#### Headers de Seguridad Adicionales

```javascript
app.use(helmet({
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
```

</div>

### Fase 4: Monitoreo y Auditoría (Continuo)

<div class="info-box">

#### Logging de Eventos de Seguridad

```javascript
// logger.js
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'security.log' })
  ]
});

// Eventos a monitorear
export const logSecurityEvent = (event, userId, details) => {
  logger.info({
    timestamp: new Date().toISOString(),
    event,
    userId,
    details,
    ip: details.ip,
    userAgent: details.userAgent
  });
};

// Usar en endpoints
app.post('/auth/login', async (req, res) => {
  // ...
  logSecurityEvent('LOGIN_SUCCESS', user.id, {
    ip: req.ip,
    userAgent: req.get('user-agent')
  });
});

app.post('/auth/refresh', async (req, res) => {
  // ...
  logSecurityEvent('TOKEN_REFRESH', payload.userId, {
    ip: req.ip
  });
});
```

#### Detección de Anomalías

```javascript
// rateLimit.js
import rateLimit from 'express-rate-limit';

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 intentos
  message: 'Demasiados intentos de login, intenta de nuevo más tarde',
  standardHeaders: true,
  legacyHeaders: false,
});

// Aplicar en rutas de auth
app.post('/auth/login', authLimiter, login);
app.post('/auth/refresh', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30 // Más permisivo para refresh
}), refresh);
```

</div>

---

## Checklist de Implementación

### Backend

- [ ] Generar claves secretas robustas (`RSA`)
- [ ] Configurar expiración de AT en 15 minutos
- [ ] Configurar expiración de RT en 7 días
- [ ] Implementar almacenamiento de RT en base de datos
- [ ] Agregar `tokenVersion` a modelo de usuario para revocación global
- [ ] Implementar rotación de RT en cada refresh
- [ ] Configurar cookies con flags correctos (httpOnly, secure, sameSite)
- [ ] Implementar middleware de autenticación
- [ ] Agregar rate limiting en endpoints de auth
- [ ] Configurar CORS correctamente
- [ ] Implementar logging de eventos de seguridad
- [ ] Agregar headers de seguridad (Helmet.js)
- [ ] Implementar CSP estricta
- [ ] Job para limpiar RTs expirados de DB

### Frontend

- [ ] Crear servicio de autenticación con métodos login/refresh/logout
- [ ] Implementar almacenamiento seguro de AT (variable privada)
- [ ] Configurar interceptores HTTP (Axios/Fetch)
- [ ] Implementar manejo de 401 con retry automático
- [ ] Agregar refresh proactivo (1 min antes de expiración)
- [ ] Implementar sincronización multi-tab (BroadcastChannel)
- [ ] Sanitizar todos los inputs de usuario
- [ ] Evitar `dangerouslySetInnerHTML` o equivalentes
- [ ] Configurar `withCredentials: true` en peticiones
- [ ] Implementar loading states durante refresh
- [ ] Agregar manejo de errores de red
- [ ] Implementar logout en todas las tabs simultáneamente

### Testing

- [ ] Test: Login exitoso
- [ ] Test: Login con credenciales inválidas
- [ ] Test: Refresh con RT válido
- [ ] Test: Refresh con RT expirado/revocado
- [ ] Test: Petición con AT válido
- [ ] Test: Petición con AT expirado (auto-refresh)
- [ ] Test: Logout limpia tokens y cookies
- [ ] Test: Rate limiting en /login
- [ ] Test: CORS permite solo dominios autorizados
- [ ] Test: Cookies tienen flags correctos
- [ ] Test: Headers de seguridad presentes
- [ ] Test: XSS no puede acceder a RT (HttpOnly)
- [ ] Test: Multi-tab logout sincronizado
- [ ] Test de penetración (contratar auditoría externa)

### Deployment

- [ ] Variables de entorno seguras (secrets en CI/CD)
- [ ] HTTPS forzado en producción
- [ ] Certificado SSL válido
- [ ] Monitoreo de tokens (tasa de refresh, fallos)
- [ ] Alertas de seguridad (intentos de login fallidos)
- [ ] Backup de base de datos de tokens
- [ ] Documentación de runbook para revocación de tokens
- [ ] Plan de respuesta a incidentes

---

## Plan B: Cuándo usar Estrategia 1

<div class="info-box warning">

### Cambia a Dual HTTPOnly si:

1. **Auditoría de Seguridad Falla**
   - Vulnerabilidades XSS encontradas y no mitigables
   - CSP no se puede implementar (legacy code)

2. **Regulaciones Estrictas**
   - PCI-DSS Level 1
   - HIPAA con datos PHI
   - SOC 2 Type II con requisitos específicos

3. **Arquitectura Simple**
   - Single-domain application
   - No hay planes de microservicios
   - No requiere mobile app nativa

### Migración de Estrategia 2 a Estrategia 1

```javascript
// Cambiar backend para enviar AT en cookie también
res.cookie('accessToken', accessToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 15 * 60 * 1000,
  path: '/'
});

// NO enviar AT en body
res.json({
  // accessToken: accessToken, // ❌ Eliminar
  user: userData
});

// Frontend simplificado
async function fetchProtectedData() {
  // ✅ Sin headers Authorization
  const response = await fetch('/api/data', {
    credentials: 'include'
  });
  return response.json();
}

// Agregar protección CSRF
import csrf from 'csurf';
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);
```

</div>

---

## Métricas de Éxito

Después de implementación, monitorear:

| Métrica | Objetivo | Acción si Falla |
|---------|----------|-----------------|
| **Tasa de éxito de login** | > 95% | Revisar UX, validaciones |
| **Tasa de éxito de refresh** | > 99% | Revisar lógica de expiración |
| **Latencia de refresh** | < 200ms | Optimizar consulta DB |
| **Intentos de login fallidos** | < 5% del total | Investigar ataques, mejorar rate limit |
| **Tokens revocados manualmente** | < 1% | Normal (logout de usuarios) |
| **Errores XSS detectados** | 0 | Revisión de código urgente |
| **Errores CSP reportados** | 0 | Ajustar política CSP |

---

## Conclusión Final

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; border-radius: 12px; margin: 2rem 0;">

### 🎯 Decisión Recomendada

**Implementar Estrategia 2 (Híbrido)** con las siguientes condiciones:

1. ✅ Content Security Policy estricta (sin `unsafe-inline` en scripts)
2. ✅ Sanitización de inputs con DOMPurify o equivalente
3. ✅ Framework moderno (React 18+, Vue 3+) con auto-sanitización
4. ✅ Access Token limitado a 15 minutos
5. ✅ Refresh Token rotado en cada uso
6. ✅ Logging y monitoreo de eventos de seguridad
7. ✅ Auditorías de seguridad periódicas

### ⚠️ Migrar a Estrategia 1 si:

- Auditoría encuentra vulnerabilidades XSS no mitigables
- Regulaciones requieren máxima seguridad
- Equipo no puede mantener CSP y sanitización

### 📈 Roadmap Post-Implementación

**Mes 1-3**: Monitoreo intensivo, ajustes basados en logs
**Mes 3-6**: Auditoría de seguridad externa
**Mes 6+**: Evaluación de migración a OAuth 2.1 o WebAuthn

</div>

---

## Recursos Adicionales

### Documentación Oficial

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [Content Security Policy Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

### Herramientas Recomendadas

- **Seguridad**: Snyk, npm audit, OWASP ZAP
- **Monitoreo**: Sentry, LogRocket, Datadog
- **Testing**: Jest, Cypress, Postman

### Comunidad y Soporte

- Stack Overflow: [jwt] [authentication] tags
- Reddit: r/webdev, r/netsec
- Discord: The Programmer's Hangout, Reactiflux

