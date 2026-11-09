import { createPublicKey, timingSafeEqual } from 'crypto';
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { GatewayProblemException } from './problemas';

export type RolUsuarioGateway = 'cliente' | 'administrador' | 'superadmin';
export type EstadoUsuarioGateway = 'activo' | 'pendiente' | 'suspendido';
export type RolV2Gateway = 'SERVICE' | 'CLIENTE' | 'ADMIN';

export type ScopeAlojamientos =
  | 'alojamientos:read'
  | 'alojamientos:book'
  | 'alojamientos:cancel'
  | 'alojamientos:checkin'
  | 'alojamientos:inventory'
  | 'alojamientos:admin'
  | 'alojamientos:webhooks';

export interface RequisitosV2Gateway {
  scope?: ScopeAlojamientos;
  bearer: boolean;
  rolesBearer?: RolV2Gateway[];
  apiKey: boolean;
}

const lectura: ScopeAlojamientos = 'alojamientos:read';
const reserva: RequisitosV2Gateway = { scope: 'alojamientos:book', bearer: true, apiKey: true };
const consulta: RequisitosV2Gateway = { scope: lectura, bearer: true, apiKey: true };
const cancelacion: RequisitosV2Gateway = { scope: 'alojamientos:cancel', bearer: true, apiKey: true };
const checkin: RequisitosV2Gateway = { scope: 'alojamientos:checkin', bearer: true, apiKey: false };
const inventario: RequisitosV2Gateway = { scope: 'alojamientos:inventory', bearer: false, apiKey: true };

// Tabla espejo del `security` de cada operación protegida del contrato v2 (§7).
export const REQUISITOS_V2_GATEWAY: Record<string, RequisitosV2Gateway> = {
  getPromotionContract: consulta,
  putPromotionContract: { scope: 'alojamientos:admin', bearer: true, rolesBearer: ['ADMIN'], apiKey: false },
  listOutboxEvents: inventario,
  createOrder: reserva,
  listOrders: { scope: lectura, bearer: true, rolesBearer: ['ADMIN'], apiKey: true },
  getOrder: consulta,
  cancelOrder: cancelacion,
  checkInOrder: checkin,
  setEarlyCheckin: { scope: 'alojamientos:admin', bearer: true, rolesBearer: ['ADMIN'], apiKey: false },
  checkOutOrder: checkin,
  listMyReservations: { bearer: true, rolesBearer: ['CLIENTE', 'ADMIN'], apiKey: false },
  getInventorySnapshot: inventario,
  createResena: { bearer: true, rolesBearer: ['CLIENTE'], apiKey: false },
  createOrder_alojamientos_reservas: reserva,
  createOrder_alojamientos_id_reservations: reserva,
  getOrder_alojamientos_reservas_id: consulta,
  getOrder_alojamientos_reservations_reservationId: consulta,
  cancelOrder_alojamientos_reservas_id_cancel: cancelacion,
  cancelOrder_alojamientos_reservations_reservationId_cancel: cancelacion,
  checkInOrder_alojamientos_reservas_id_checkin: checkin,
  checkInOrder_alojamientos_reservations_reservationId_checkin: checkin,
  checkOutOrder_alojamientos_reservas_id_checkout: checkin,
  checkOutOrder_alojamientos_reservations_reservationId_checkout: checkin,
  createResena_alojamientos_id_reviews: { bearer: true, rolesBearer: ['CLIENTE'], apiKey: false },
};

export interface PrincipalGateway {
  tipo: 'usuario' | 'servicio' | 'apikey';
  via: 'usuario' | 'oauth' | 'apikey';
  usuarioId?: string;
  rolUsuario?: RolUsuarioGateway;
  estadoUsuario?: EstadoUsuarioGateway;
  rolV2: RolV2Gateway;
  superadmin?: boolean;
  scopes?: string[];
}

export interface ReglaSeguridadRuta {
  acceso: 'publica' | 'v1_protegida' | 'v2_protegida' | 'graphql';
  rolesPermitidos?: RolUsuarioGateway[];
  scopeRequerido?: ScopeAlojamientos;
  scopeOpcional?: ScopeAlojamientos;
  operacionV2?: string;
}

interface CargaTokenBruta {
  sub?: string;
  rol?: RolUsuarioGateway;
  estado?: EstadoUsuarioGateway;
  roles?: string[];
  scope?: string;
  scp?: string[] | string;
  iat?: number;
  exp?: number;
}

const ES_UUID = /^[0-9a-f-]{36}$/i;
const ROLES_USUARIO_VALIDOS = new Set<string>(['cliente', 'administrador', 'superadmin']);
const ESTADOS_USUARIO_VALIDOS = new Set<string>(['activo', 'pendiente', 'suspendido']);
const LARGO_MINIMO_SECRETO = 32;
const LARGO_MINIMO_API_KEY = 16;
const VIDA_MAXIMA_OAUTH_DEFECTO_S = 900;

export function normalizarPem(valor: string | undefined): string | undefined {
  const limpio = valor?.trim().replace(/\\n/g, '\n');
  return limpio && limpio.length > 0 ? limpio : undefined;
}

export function extraerScopes(carga: CargaTokenBruta): string[] | null {
  const bruto = carga.scope ?? carga.scp;
  if (bruto === undefined) return null;
  const lista = Array.isArray(bruto) ? bruto : String(bruto).split(/\s+/);
  return lista.filter((s) => typeof s === 'string' && s.length > 0);
}

export function ahoraDePrueba(req: Pick<Request, 'header'>): Date | undefined {
  if (process.env.V2_CABECERAS_PRUEBA?.trim().toLowerCase() !== 'true') return undefined;
  const valor = req.header('x-prueba-token-ahora')?.trim();
  if (!valor) return undefined;
  const ms = Date.parse(valor);
  return Number.isFinite(ms) ? new Date(ms) : undefined;
}

function igualSeguro(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function resolverClavePublicaRsa(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const publica = normalizarPem(env.JWT_PUBLIC_KEY);
  if (publica) return publica;
  const privada = normalizarPem(env.JWT_PRIVATE_KEY);
  if (privada) {
    return createPublicKey(privada).export({ type: 'spki', format: 'pem' }).toString();
  }
  return undefined;
}

@Injectable()
export class SeguridadJwtGatewayService {
  private readonly jwt = new JwtService();
  private clavePublicaRemotaCache?: string;

  /**
   * Resuelve el modo de verificación JWT del gateway (D3):
   * - Si hay `JWT_PUBLIC_KEY` (o `JWT_PRIVATE_KEY` de la cual derivar la pública), verifica con RS256.
   * - Si no hay clave RSA local pero el servicio `usuarios` expone su clave pública, puede consultarla.
   * - Solo usa `JWT_SECRET` (HS256) como respaldo de pruebas cuando no hay par RSA.
   */
  resolverVerificadorUi(env: NodeJS.ProcessEnv = process.env): {
    modo: 'rs256' | 'hs256' | 'ninguno';
    publicKey?: string;
    secret?: string;
    issuer?: string;
    audience?: string;
  } {
    const publicKey = resolverClavePublicaRsa(env) ?? this.clavePublicaRemotaCache;
    const issuer = env.JWT_ISSUER?.trim() || undefined;
    const audience = env.JWT_AUDIENCE?.trim() || undefined;
    if (publicKey) {
      return { modo: 'rs256', publicKey, issuer, audience };
    }
    const secret = env.JWT_SECRET?.trim();
    if (secret && secret.length >= LARGO_MINIMO_SECRETO) {
      return { modo: 'hs256', secret, issuer, audience };
    }
    return { modo: 'ninguno', issuer, audience };
  }

  /**
   * Fija o actualiza en memoria la clave pública RSA (por ejemplo tras consultarla a `usuarios`).
   */
  fijarClavePublicaRemota(publicKeyPem: string | undefined): void {
    this.clavePublicaRemotaCache = normalizarPem(publicKeyPem);
  }

  /**
   * Verifica un token Bearer con la clave pública RS256 (o el respaldo HS256 de pruebas).
   * Soporta tanto tokens de sesión de usuario de Cozy (`sub`, `rol`, `estado`) como tokens con
   * `scope`/`scp` (`alojamientos:book`, `alojamientos:read`, etc.) o `roles` (`CLIENTE`, `ADMIN`).
   */
  async verificarTokenBearer(
    cabeceraAuth: string | undefined,
    ahora?: Date,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<PrincipalGateway> {
    const token = this.extraerBearer(cabeceraAuth);
    if (!token) {
      throw new GatewayProblemException(401, 'UNAUTHORIZED', 'Se requiere un token de autenticación');
    }

    // 1. Si hay emisor OAuth2 configurado o el token trae scopes, intentamos verificarlo como token OAuth2 o con la clave RS256
    const desdeOauth = await this.intentarVerificarOauth(token, ahora, env);
    if (desdeOauth) return desdeOauth;

    // 2. Verificación con la clave pública RS256 de usuarios (D3) o JWT_SECRET de respaldo para pruebas
    const configUi = this.resolverVerificadorUi(env);
    if (configUi.modo === 'ninguno') {
      throw new GatewayProblemException(401, 'UNAUTHORIZED', 'El token no es válido o venció: inicia sesión de nuevo');
    }

    let carga: CargaTokenBruta;
    try {
      carga = await this.jwt.verifyAsync<CargaTokenBruta>(token, {
        ...(configUi.modo === 'rs256'
          ? { publicKey: configUi.publicKey, algorithms: ['RS256'] }
          : { secret: configUi.secret, algorithms: ['HS256'] }),
        ...(configUi.issuer && { issuer: configUi.issuer }),
        ...(configUi.audience && { audience: configUi.audience }),
        ...(ahora && { clockTimestamp: Math.floor(ahora.getTime() / 1000) }),
      });
    } catch {
      throw new GatewayProblemException(401, 'UNAUTHORIZED', 'El token no es válido o venció: inicia sesión de nuevo');
    }

    return this.interpretarCargaVerificada(carga);
  }

  /**
   * Verifica y autoriza el acceso a una ruta según sus reglas de seguridad (v1 pública/protegida, scopes o v2).
   */
  async verificarAccesoRuta(
    req: Request & { principalGateway?: { rol: string; via: string; usuarioId?: string } },
    regla: ReglaSeguridadRuta,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<PrincipalGateway | null> {
    const ahora = ahoraDePrueba(req);

    if (regla.acceso === 'graphql') {
      if (req.headers.authorization) {
        const principal = await this.verificarTokenBearer(req.headers.authorization, ahora, env);
        req.principalGateway = {
          rol: principal.rolUsuario ?? principal.rolV2,
          via: principal.via,
          usuarioId: principal.usuarioId,
        };
        return principal;
      }
      return null;
    }

    if (regla.acceso === 'publica') {
      // Si la ruta pública admite un token con scope (p. ej. /api/v1/orders/*, /api/v1/webhooks*) y el llamador envía un Bearer con scope:
      if (regla.scopeOpcional && req.headers.authorization) {
        const principalOpcional = await this.verificarTokenScopeOpcional(req.headers.authorization, ahora, env);
        if (principalOpcional) {
          this.exigirScope(principalOpcional, regla.scopeOpcional);
          req.principalGateway = {
            rol: principalOpcional.rolV2,
            via: principalOpcional.via,
            usuarioId: principalOpcional.usuarioId,
          };
          return principalOpcional;
        }
      }
      return null;
    }

    if (regla.acceso === 'v1_protegida') {
      const principal = await this.verificarTokenBearer(req.headers.authorization, ahora, env);
      if (regla.scopeRequerido) {
        this.exigirScope(principal, regla.scopeRequerido);
      }
      if (regla.rolesPermitidos && regla.rolesPermitidos.length > 0) {
        this.exigirRolUsuario(principal, regla.rolesPermitidos);
      }
      req.principalGateway = {
        rol: principal.rolUsuario ?? principal.rolV2,
        via: principal.via,
        usuarioId: principal.usuarioId,
      };
      return principal;
    }

    // regla.acceso === 'v2_protegida'
    const requisitos = regla.operacionV2 ? REQUISITOS_V2_GATEWAY[regla.operacionV2] : undefined;
    if (!requisitos) {
      throw new GatewayProblemException(403, 'FORBIDDEN', 'La operación no declara qué credenciales admite.');
    }

    const principal = await this.autenticarPeticionV2(req, ahora, env);
    this.autorizarOperacionV2(principal, requisitos);
    req.principalGateway = {
      rol: principal.rolV2,
      via: principal.via,
      usuarioId: principal.usuarioId,
    };
    return principal;
  }

  /**
   * Comprueba que el principal tenga uno de los roles de usuario permitidos en rutas v1.
   */
  exigirRolUsuario(principal: PrincipalGateway, rolesPermitidos: RolUsuarioGateway[]): void {
    if (!principal.rolUsuario || !rolesPermitidos.includes(principal.rolUsuario)) {
      throw new GatewayProblemException(403, 'FORBIDDEN', 'Tu rol no tiene permiso para esta operación');
    }
  }

  /**
   * Comprueba que el principal incluya el scope exigido por la operación (`alojamientos:book`, `alojamientos:read`, etc.).
   */
  exigirScope(principal: PrincipalGateway, scopeRequerido: ScopeAlojamientos): void {
    if (!principal.scopes || !principal.scopes.includes(scopeRequerido)) {
      throw new GatewayProblemException(403, 'INSUFFICIENT_SCOPE', 'El token no incluye el scope requerido.', {
        scopes_requeridos: [scopeRequerido],
      });
    }
  }

  /**
   * Autoriza un principal contra los requisitos de una operación del contrato v2 (`REQUISITOS_V2_GATEWAY`).
   */
  autorizarOperacionV2(principal: PrincipalGateway, requisitos: RequisitosV2Gateway): void {
    if (principal.via === 'apikey') {
      if (!requisitos.apiKey) {
        throw new GatewayProblemException(403, 'FORBIDDEN', 'La X-API-Key no sirve para esta operación.');
      }
      return;
    }
    if (principal.via === 'oauth') {
      if (!requisitos.scope) {
        throw new GatewayProblemException(403, 'FORBIDDEN', 'Un token de servicio no sirve para esta operación.');
      }
      if (!principal.scopes?.includes(requisitos.scope)) {
        throw new GatewayProblemException(403, 'INSUFFICIENT_SCOPE', 'El token no incluye el scope requerido.', {
          scopes_requeridos: [requisitos.scope],
        });
      }
      return;
    }
    if (!requisitos.bearer) {
      throw new GatewayProblemException(403, 'FORBIDDEN', 'Un token de usuario no sirve para esta operación.');
    }
    if (requisitos.rolesBearer && !requisitos.rolesBearer.includes(principal.rolV2)) {
      throw new GatewayProblemException(
        403,
        'FORBIDDEN',
        `Esta operación requiere el rol ${requisitos.rolesBearer.join(' o ')}.`,
      );
    }
  }

  private async autenticarPeticionV2(
    req: Request,
    ahora?: Date,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<PrincipalGateway> {
    const apiKey = req.header('x-api-key');
    if (apiKey !== undefined) {
      const esperada = env.V2_API_KEY?.trim();
      // Si el gateway tiene V2_API_KEY configurada la valida aquí; si no está en el env del gateway,
      // comprueba al menos formato no vacío y deja que el servicio valide el valor exacto.
      if (esperada) {
        if (esperada.length < LARGO_MINIMO_API_KEY || !igualSeguro(apiKey, esperada)) {
          throw new GatewayProblemException(401, 'UNAUTHORIZED', 'La X-API-Key no es válida.');
        }
      } else if (apiKey.trim().length < LARGO_MINIMO_API_KEY) {
        throw new GatewayProblemException(401, 'UNAUTHORIZED', 'La X-API-Key no es válida.');
      }
      return { tipo: 'apikey', via: 'apikey', rolV2: 'SERVICE' };
    }

    if (!req.headers.authorization) {
      throw new GatewayProblemException(
        401,
        'UNAUTHORIZED',
        'Esta operación exige credenciales: Authorization: Bearer <token> o X-API-Key.',
      );
    }

    try {
      return await this.verificarTokenBearer(req.headers.authorization, ahora, env);
    } catch (error) {
      if (error instanceof GatewayProblemException) {
        if (error.estado === 403 && (error.codigo === 'ACCOUNT_PENDING' || error.codigo === 'ACCOUNT_SUSPENDED')) {
          throw new GatewayProblemException(403, 'FORBIDDEN', 'La cuenta no está activa.');
        }
        throw error;
      }
      throw new GatewayProblemException(401, 'UNAUTHORIZED', 'El token no es válido o venció.');
    }
  }

  private async intentarVerificarOauth(
    token: string,
    ahora?: Date,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<PrincipalGateway | null> {
    const secretoOauth = env.OAUTH_JWT_SECRET?.trim();
    const secretoValido = secretoOauth && secretoOauth.length >= LARGO_MINIMO_SECRETO ? secretoOauth : undefined;
    const clavePublicaOauth = normalizarPem(env.OAUTH_JWT_PUBLIC_KEY);
    if (!secretoValido && !clavePublicaOauth) return null;

    const emisor = env.OAUTH_ISSUER?.trim() || undefined;
    const audiencia = env.OAUTH_AUDIENCE?.trim() || undefined;
    const vidaMaximaS = Number(env.OAUTH_VIDA_MAX_S) > 0 ? Number(env.OAUTH_VIDA_MAX_S) : VIDA_MAXIMA_OAUTH_DEFECTO_S;

    let carga: CargaTokenBruta;
    try {
      carga = await this.jwt.verifyAsync<CargaTokenBruta>(token, {
        ...(secretoValido
          ? { secret: secretoValido, algorithms: ['HS256'] }
          : { publicKey: clavePublicaOauth, algorithms: ['RS256', 'ES256'] }),
        ...(emisor && { issuer: emisor }),
        ...(audiencia && { audience: audiencia }),
        ...(ahora && { clockTimestamp: Math.floor(ahora.getTime() / 1000) }),
        clockTolerance: 5,
      });
    } catch (error) {
      if ((error as Error).name === 'TokenExpiredError') {
        throw new GatewayProblemException(401, 'UNAUTHORIZED', 'El token venció.');
      }
      return null;
    }

    if (!carga.exp || !carga.iat || carga.exp - carga.iat > vidaMaximaS) {
      throw new GatewayProblemException(
        401,
        'UNAUTHORIZED',
        `El token debe vivir como máximo ${Math.round(vidaMaximaS / 60)} minutos.`,
      );
    }

    const scopes = extraerScopes(carga);
    if (scopes) {
      return { tipo: 'servicio', via: 'oauth', usuarioId: carga.sub, rolV2: 'SERVICE', scopes };
    }
    const roles = Array.isArray(carga.roles) ? carga.roles : [];
    if (typeof carga.sub === 'string' && roles.includes('ADMIN')) {
      return {
        tipo: 'usuario',
        via: 'usuario',
        usuarioId: carga.sub,
        rolUsuario: 'superadmin',
        estadoUsuario: 'activo',
        rolV2: 'ADMIN',
        superadmin: true,
      };
    }
    if (typeof carga.sub === 'string' && roles.includes('CLIENTE')) {
      return {
        tipo: 'usuario',
        via: 'usuario',
        usuarioId: carga.sub,
        rolUsuario: 'cliente',
        estadoUsuario: 'activo',
        rolV2: 'CLIENTE',
      };
    }
    throw new GatewayProblemException(401, 'UNAUTHORIZED', 'El token no trae ni scope ni roles reconocidos.');
  }

  private interpretarCargaVerificada(carga: CargaTokenBruta): PrincipalGateway {
    const scopes = extraerScopes(carga);

    // Si es un token de sesión de usuario de Cozy (con sub UUID, rol y estado)
    if (
      typeof carga?.sub === 'string' &&
      ES_UUID.test(carga.sub) &&
      typeof carga.rol === 'string' &&
      ROLES_USUARIO_VALIDOS.has(carga.rol) &&
      typeof carga.estado === 'string' &&
      ESTADOS_USUARIO_VALIDOS.has(carga.estado)
    ) {
      if (carga.estado === 'pendiente') {
        throw new GatewayProblemException(
          403,
          'ACCOUNT_PENDING',
          'Tu cuenta de administrador está pendiente de aprobación por el superadmin',
        );
      }
      if (carga.estado === 'suspendido') {
        throw new GatewayProblemException(403, 'ACCOUNT_SUSPENDED', 'Tu cuenta está suspendida');
      }
      const rolV2: RolV2Gateway = carga.rol === 'cliente' ? 'CLIENTE' : 'ADMIN';
      return {
        tipo: 'usuario',
        via: scopes ? 'oauth' : 'usuario',
        usuarioId: carga.sub,
        rolUsuario: carga.rol,
        estadoUsuario: carga.estado,
        rolV2,
        superadmin: carga.rol === 'superadmin',
        ...(scopes && { scopes }),
      };
    }

    // Si es un token de servicio con scopes (firmado con la clave privada RS256)
    if (scopes) {
      const vidaMaximaS =
        Number(process.env.OAUTH_VIDA_MAX_S) > 0 ? Number(process.env.OAUTH_VIDA_MAX_S) : VIDA_MAXIMA_OAUTH_DEFECTO_S;
      if (carga.exp && carga.iat && carga.exp - carga.iat > vidaMaximaS) {
        throw new GatewayProblemException(
          401,
          'UNAUTHORIZED',
          `El token debe vivir como máximo ${Math.round(vidaMaximaS / 60)} minutos.`,
        );
      }
      return {
        tipo: 'servicio',
        via: 'oauth',
        usuarioId: carga.sub,
        rolV2: 'SERVICE',
        scopes,
      };
    }

    const roles = Array.isArray(carga?.roles) ? carga.roles : [];
    if (typeof carga?.sub === 'string' && roles.includes('ADMIN')) {
      return {
        tipo: 'usuario',
        via: 'usuario',
        usuarioId: carga.sub,
        rolUsuario: 'superadmin',
        estadoUsuario: 'activo',
        rolV2: 'ADMIN',
        superadmin: true,
      };
    }
    if (typeof carga?.sub === 'string' && roles.includes('CLIENTE')) {
      return {
        tipo: 'usuario',
        via: 'usuario',
        usuarioId: carga.sub,
        rolUsuario: 'cliente',
        estadoUsuario: 'activo',
        rolV2: 'CLIENTE',
      };
    }

    throw new GatewayProblemException(401, 'UNAUTHORIZED', 'El token no es válido o venció: inicia sesión de nuevo');
  }

  private async verificarTokenScopeOpcional(
    cabeceraAuth: string | undefined,
    ahora?: Date,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<PrincipalGateway | null> {
    try {
      const principal = await this.verificarTokenBearer(cabeceraAuth, ahora, env);
      // Si es un token de servicio (via === 'oauth') o trae scopes explícitos, devolvemos el principal para validar su scope.
      if (principal.via === 'oauth' || principal.scopes) {
        return principal;
      }
      return null;
    } catch {
      return null;
    }
  }

  private extraerBearer(cabecera: string | undefined): string | null {
    const partes = (cabecera ?? '').trim().split(/\s+/);
    return partes.length === 2 && /^bearer$/i.test(partes[0]) ? partes[1] : null;
  }
}

