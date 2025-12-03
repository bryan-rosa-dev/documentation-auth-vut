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
// auth.service.js
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { RedisAuthService } from './infra/cache/redis-auth.service';
import { UsersService } from '../users/users.service';
import type { IPasswordHasher } from './domain/ports/password-hasher.port';
import { AUTH_PORTS } from './domain/ports/tokens';
import { UserAuthRecord, UserRecord } from '../users/domain/models/users.type';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { CustomJwtPayload } from '@modules/jwt/domain/models/payload.type';
import {
  SingleTokenIssue,
  TokenPair,
} from '@modules/jwt/domain/models/token-issuer.type';
import { SessionsService } from './sessions.service';
import {
  formatDate,
  parseDate,
} from 'src/libs/shared-helpers/parse-date.helper';
import { JwtCustomService } from '@modules/jwt/jwt.service';

@Injectable()
export class AuthService {
  constructor(
    @Inject(AUTH_PORTS.PasswordHasher) private readonly hasher: IPasswordHasher,
    private readonly tokenService: JwtCustomService,
    private readonly cache: RedisAuthService,
    private readonly usersService: UsersService,
    private readonly cfg: ConfigService,
    private readonly sessionsService: SessionsService,
  ) {}

  async authUser(data: {
    dni: string;
    password: string;
    ipAddress?: string;
    userAgent?: string;
  }) {
    const errorMessage = 'Invalid credentials';
    const user = (await this.usersService.findByDni(
      data.dni,
      true,
    )) as UserAuthRecord;

    if (!user) throw new UnauthorizedException(errorMessage);

    const ok = await this.hasher.compare(data.password, user.password);

    if (!ok) throw new UnauthorizedException(errorMessage);

    const twoFactorEnabled = this.cfg.get<boolean>('APP_2FA_REQUIRED') || false;
    const twoFactorUserEnabled = user?.mfaEnabled || false;

    if (twoFactorEnabled && twoFactorUserEnabled) {
      return await this.mfaLogin(user);
    }

    return await this.login(user, data.ipAddress, data.userAgent);
  }

  private async login(
    user: UserAuthRecord,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const sid = randomUUID();

    const pair: TokenPair = await this.generateTokens(user, sid);

    const rtHashed = await this.hasher.hash(pair.refresh_token);

    await this.sessionsService.createSession(
      sid,
      pair.refresh_jti,
      user.id,
      pair.refresh_expires_at,
      ipAddress,
      userAgent,
      rtHashed,
    );

    return pair;
  }

  private async generateTokens(
    user: UserAuthRecord | UserRecord,
    sid: string,
  ): Promise<TokenPair> {
    const payload: CustomJwtPayload = {
      sub: String(user.id),
      email: user.email,
      sid: sid,
      dni: user.dni,
      jti: randomUUID(),
      purpose: 'at',
    };

    const pair: TokenPair = await this.tokenService.issueAuthTokens(payload);

    if (!pair) throw new UnauthorizedException('Token generation failed');

    return pair;
  }

  async logout(data: CustomJwtPayload) {
    if (data.jti && data.exp) {
      const ttlSec = Math.max(1, data.exp - Math.floor(Date.now() / 1000));

      await this.cache.blacklistToken('RT', data.jti, ttlSec);
    }

    if (data.sid && isNaN(data.sid as any)) {
      await this.sessionsService.closeSession(data.sid, Number(data.sub));
    }

    return { ok: true };
  }

  async rotate(data: CustomJwtPayload) {
    const errorMessage = 'Unauthorized refresh token';
    if (!data.rt) throw new UnauthorizedException(errorMessage);

    if (!data.jti) throw new UnauthorizedException(errorMessage);

    const blacklisted = await this.cache.isBlacklisted('RT', data.jti);
    if (blacklisted) throw new UnauthorizedException(errorMessage);

    const session = await this.sessionsService.getSessionById(
      data.sid!,
      Number(data.sub),
      true,
    );

    if (!session) throw new UnauthorizedException(errorMessage);

    const rtMatches = await this.hasher.compare(
      data.rt,
      session.hashedRt || '',
    );

    if (!rtMatches) throw new UnauthorizedException(errorMessage);

    const user = await this.usersService.findById(Number(data.sub));

    if (!user) throw new UnauthorizedException(errorMessage);

    const pair: TokenPair = await this.generateTokens(user, data.sid!);

    const rtHashed = await this.hasher.hash(pair.refresh_token);

    await this.sessionsService.updateSession(
      session.id,
      pair.refresh_jti,
      user.id,
      pair.refresh_expires_at,
      session.ip,
      session.userAgent,
      rtHashed,
    );

    const ttlSec = Math.max(1, data.exp! - Math.floor(Date.now() / 1000));
    await this.cache.blacklistToken('RT', data.jti, ttlSec);

    return pair;
  }
}

```

#### TokenService

```javascript
//jwt.service.ts
import { Inject, Injectable } from '@nestjs/common';
import { createSecretKey, randomUUID } from 'crypto';
import {
  createRemoteJWKSet,
  exportJWK,
  importPKCS8,
  importSPKI,
  jwtVerify,
  SignJWT,
  type JWTPayload,
} from 'jose';
import {
  IssuerJwksConfig,
  RsaKeyEntry,
  type SecretManager,
} from '@modules/secrets/secret-manager.interface';
import { SECRET_MANAGER } from '@modules/secrets/secret-manager.module';
import type { CustomJwtPayload } from './domain/models/payload.type';
import { toSeconds } from 'src/libs/shared-helpers/string-to-seconds.helper';
import { SingleTokenIssue, TokenPair } from './domain/models/token-issuer.type';

@Injectable()
export class JwtCustomService {
  private rsaKeyCache = new Map<
    string,
    { privateKey: CryptoKey; publicKey: CryptoKey }
  >();
  private jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

  constructor(
    @Inject(SECRET_MANAGER) private readonly secretManager: SecretManager,
  ) {}

  async signWithRsa(
    alias: string,
    payload: CustomJwtPayload,
    options?: {
      expiresIn?: string | number;
      issuer?: string;
      audience?: string | string[];
      keyId?: string;
      algorithm?: 'RS256' | 'RS384' | 'RS512';
    },
  ): Promise<SingleTokenIssue> {
    const entry = await this.getRsaEntry(alias);
    const keys = await this.getRsaKeys(alias, entry);
    const alg = options?.algorithm ?? 'RS256';
    const exp = this.resolveExpiration(options?.expiresIn, payload.exp, entry);
    const issuer = options?.issuer ?? payload.iss ?? entry.iss;
    const audience = options?.audience ?? payload.aud ?? entry.aud;
    const kid = options?.keyId ?? entry.kid;

    const signer = new SignJWT(payload as JWTPayload)
      .setProtectedHeader({ alg, ...(kid ? { kid } : {}) })
      .setIssuedAt()
      .setSubject(String(payload.sub));

    if (exp !== undefined) signer.setExpirationTime(exp);
    if (issuer) signer.setIssuer(issuer);
    if (audience) signer.setAudience(audience);

    const token = await signer.sign(keys.privateKey);

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expires_at = exp ? new Date(exp * 1000) : new Date(0);
    const expires_in = exp ? exp - nowSeconds : undefined;

    return {
      token,
      expires_at: expires_at,
      expires_in: expires_in,
    };
  }

  async issueAuthTokens(payload: CustomJwtPayload): Promise<TokenPair> {
    const accessJti = randomUUID();
    const refreshJti = randomUUID();
    const access = await this.signWithRsa('at', {...payload,jti:accessJti});
    const refresh = await this.signWithRsa('rt', {...payload,jti:refreshJti});

    return {
      token_type: 'Bearer',
      access_token: access.token,
      access_expires_at: access.expires_at,
      access_expires_in: access.expires_in,
      refresh_token: refresh.token,
      refresh_expires_at: refresh.expires_at,
      refresh_expires_in: refresh.expires_in,
      access_jti: accessJti,
      refresh_jti: refreshJti,
    } as TokenPair;
  }

  async verifyWithRsa(
    token: string,
    alias: string,
    options?: {
      issuer?: string;
      audience?: string | string[];
      expectedKid?: string;
    },
  ): Promise<CustomJwtPayload> {
    const entry = await this.getRsaEntry(alias);
    const keys = await this.getRsaKeys(alias, entry);
    const { payload, protectedHeader } = await jwtVerify(
      token,
      keys.publicKey,
      {
        issuer: options?.issuer ?? entry.iss,
        audience: options?.audience ?? entry.aud,
      },
    );
    this.assertKidMatch(entry.kid, protectedHeader.kid, `rsa:${alias}`);
    this.assertKidMatch(
      options?.expectedKid,
      protectedHeader.kid,
      `rsa:${alias}`,
    );
    return payload as CustomJwtPayload;
  }

  async verifyWithJwks(
    token: string,
    issuerAlias: string,
    options?: {
      issuer?: string;
      audience?: string | string[];
      expectedKid?: string;
    },
  ): Promise<CustomJwtPayload> {
    const issuerMap = await this.secretManager.getIssuerMap();
    const issuer = issuerMap[issuerAlias];
    if (!issuer) {
      throw new Error(`Issuer alias "${issuerAlias}" not found in issuer map`);
    }

    const jwks = this.getRemoteJwks(issuerAlias, issuer);
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: options?.issuer ?? issuer.expectedIss,
      audience: options?.audience ?? issuer.expectedAud,
    });
    this.assertKidMatch(
      options?.expectedKid,
      protectedHeader.kid,
      `jwks:${issuerAlias}`,
    );
    return payload as CustomJwtPayload;
  }

  async getPublicJwks(): Promise<{ keys: Array<Record<string, unknown>> }> {
    const map = await this.secretManager.getRsaKeyMap();
    const keys: Array<Record<string, unknown>> = [];

    for (const [alias, entry] of Object.entries(map)) {
      if (!entry.exposeInJwks) continue;

      const { publicKey } = await this.getRsaKeys(alias, entry);
      const jwk = await exportJWK(publicKey);
      keys.push({
        ...jwk,
        use: 'sig',
        alg: 'RS256',
        kid: entry.kid ?? alias,
      });
    }

    return { keys };
  }

  private async getRsaEntry(alias: string): Promise<RsaKeyEntry> {
    const map = await this.secretManager.getRsaKeyMap();
    const entry = map[alias];
    if (!entry) {
      throw new Error(`RSA entry "${alias}" not found`);
    }
    return entry;
  }

  private async getRsaKeys(
    alias: string,
    entry: RsaKeyEntry,
  ): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
    const cached = this.rsaKeyCache.get(alias);
    if (cached) {
      return cached;
    }

    const privateKey = await importPKCS8(entry.privateKey, 'RS256');
    const publicKey = await importSPKI(entry.publicKey, 'RS256');
    const result = { privateKey, publicKey };
    this.rsaKeyCache.set(alias, result);
    return result;
  }

  private getRemoteJwks(
    alias: string,
    issuer: IssuerJwksConfig,
  ): ReturnType<typeof createRemoteJWKSet> {
    const cached = this.jwksCache.get(alias);
    if (cached) {
      return cached;
    }

    const remote = createRemoteJWKSet(new URL(issuer.jwksUrl), {
      cacheMaxAge: issuer.cacheTtlMs,
    });
    this.jwksCache.set(alias, remote);
    return remote;
  }

  private resolveExpiration(
    expiresIn: string | number | undefined,
    absoluteExp: number | undefined,
    source: HmacSecretConfig | RsaKeyEntry,
  ): number | undefined {
    if (absoluteExp !== undefined && expiresIn === undefined) {
      return absoluteExp;
    }

    const nowSeconds = Math.floor(Date.now() / 1000);

    if ('expiresInSeconds' in source) {
      const fallback = source.expiresInSeconds ?? 15 * 60;
      const durationSeconds =
        expiresIn === undefined ? fallback : toSeconds(expiresIn, fallback);
      return nowSeconds + durationSeconds;
    }

    const fallback = toSeconds(source.expirationTime, 15 * 60);
    const durationSeconds =
      expiresIn === undefined ? fallback : toSeconds(expiresIn, fallback);
    return nowSeconds + durationSeconds;
  }

  private assertKidMatch(
    expectedKid: string | undefined,
    actualKid: string | undefined,
    context: string,
  ): void {
    if (!expectedKid) return;
    if (!actualKid) {
      throw new Error(
        `Token is missing kid but "${context}" expects "${expectedKid}"`,
      );
    }
    if (expectedKid !== actualKid) {
      throw new Error(
        `Token kid "${actualKid}" does not match expected "${expectedKid}" for ${context}`,
      );
    }
  }
}

```

#### Guard de Autenticación

```javascript
// access-token.guard.js
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';

import { JwtCustomService } from '@modules/jwt/jwt.service';
import type { CustomJwtPayload } from '@modules/jwt/domain/models/payload.type';

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(private readonly jwt: JwtCustomService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const token = this.extractBearer(req);
    if (!token) {
      throw new UnauthorizedException('Missing access token');
    }

    try {
      const payload = await this.jwt.verifyWithRsa(token, 'at');
      (req as any).user = payload as CustomJwtPayload;
      return true;
    } catch (err) {
      throw new UnauthorizedException('Invalid access token');
    }
  }

  private extractBearer(req: Request): string | undefined {
    const header = req.headers.authorization;
    if (!header) return undefined;
    const [scheme, value] = header.split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !value) return undefined;
    return value;
  }
}
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

