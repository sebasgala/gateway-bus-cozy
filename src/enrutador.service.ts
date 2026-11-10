import { Injectable } from '@nestjs/common';
import { Request, Response } from 'express';
import { PeticionGateway, plantillaDeRuta } from './correlacion-y-logs';
import {
  CodigoErrorGateway,
  esRutaV2,
  GatewayProblemException,
  responderProblemaGateway,
} from './problemas';
import { ReglaSeguridadRuta, SeguridadJwtGatewayService } from './seguridad-jwt.service';

export type ServicioDestino =
  | 'usuarios'
  | 'catalogo'
  | 'disponibilidad'
  | 'reservas'
  | 'event-bus'
  | 'graphql';

export interface RutaResuelta {
  servicio: ServicioDestino;
  plantilla: string;
  seguridad: ReglaSeguridadRuta;
}

const PUERTOS_DEFECTO: Record<ServicioDestino, number> = {
  usuarios: 3001,
  catalogo: 3002,
  disponibilidad: 3003,
  reservas: 3004,
  'event-bus': 3005,
  graphql: 3006,
};

const VARIABLES_URL: Record<ServicioDestino, string> = {
  usuarios: 'USUARIOS_URL',
  catalogo: 'CATALOGO_URL',
  disponibilidad: 'DISPONIBILIDAD_URL',
  reservas: 'RESERVAS_URL',
  'event-bus': 'EVENT_BUS_URL',
  graphql: 'GRAPHQL_URL',
};

const CABECERAS_ENTRADA_REENVIADAS = [
  'accept',
  'accept-language',
  'authorization',
  'content-type',
  'cookie',
  'idempotency-key',
  'if-none-match',
  'user-agent',
  'x-api-key',
  'x-correlation-id',
  'x-device-fingerprint',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-node-id',
  'x-prueba-ahora',
  'x-prueba-desfase-ms',
  'x-prueba-retraso-ms',
  'x-prueba-token-ahora',
] as const;

const CABECERAS_SALIDA_REENVIADAS = [
  'cache-control',
  'content-type',
  'etag',
  'idempotent-replayed',
  'location',
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
  'retry-after',
  'set-cookie',
  'strict-transport-security',
  'www-authenticate',
  'x-api-deprecation-date',
  'x-correlation-id',
  'x-node-id',
  'x-prueba-desfase-ms',
] as const;

export function resolverUrlServicio(
  servicio: ServicioDestino,
  env: NodeJS.ProcessEnv = process.env,
): string {
  if (servicio === 'event-bus') {
    const explicita = env.FEED_URL?.trim() || env.COMUN_URL?.trim() || env.EVENT_BUS_URL?.trim() || env.BACKEND_URL?.trim();
    if (explicita) return explicita.replace(/\/+$/, '');
  } else {
    const variable = VARIABLES_URL[servicio];
    const explicita = env[variable]?.trim() || env.BACKEND_URL?.trim();
    if (explicita) return explicita.replace(/\/+$/, '');
  }
  return `http://localhost:${PUERTOS_DEFECTO[servicio]}`;
}

/**
 * Resuelve a qué microservicio, con qué plantilla de ruta y con qué regla de seguridad
 * corresponde una petición pública entrante (§5 de docs/integracion-v2/diseno-fase-9.md).
 */
export function resolverDestinoRuta(metodo: string, pathnameOriginal: string): RutaResuelta | null {
  const m = metodo.toUpperCase();
  const pathname = pathnameOriginal.split('?')[0].replace(/\/+$/, '') || '/';

  // ── 1. GraphQL (/graphql) ──
  if (pathname === '/graphql' || pathname.startsWith('/graphql/')) {
    return {
      servicio: 'graphql',
      plantilla: '/graphql',
      seguridad: { acceso: 'graphql' },
    };
  }

  // ── 2. Espacio /api/v1 ──
  if (pathname.startsWith('/api/v1/')) {
    const sub = pathname.slice('/api/v1'.length); // empieza con '/'

    // 2.1 Autenticación y clave pública (/api/v1/auth/* y /api/v1/interno/usuarios/clave-publica) -> usuarios
    if (sub === '/auth/registro' && m === 'POST') {
      return { servicio: 'usuarios', plantilla: '/api/v1/auth/registro', seguridad: { acceso: 'publica' } };
    }
    if (sub === '/auth/login' && m === 'POST') {
      return { servicio: 'usuarios', plantilla: '/api/v1/auth/login', seguridad: { acceso: 'publica' } };
    }
    if (sub === '/auth/renovar' && m === 'POST') {
      return {
        servicio: 'usuarios',
        plantilla: '/api/v1/auth/renovar',
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['cliente', 'administrador', 'superadmin'] },
      };
    }
    if (sub === '/auth/me' && m === 'GET') {
      return {
        servicio: 'usuarios',
        plantilla: '/api/v1/auth/me',
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['cliente', 'administrador', 'superadmin'] },
      };
    }
    if (sub.startsWith('/auth/')) {
      return {
        servicio: 'usuarios',
        plantilla: plantillaDeRuta(pathname),
        seguridad: { acceso: 'publica' },
      };
    }
    if (sub === '/interno/usuarios/clave-publica' && m === 'GET') {
      return {
        servicio: 'usuarios',
        plantilla: '/api/v1/interno/usuarios/clave-publica',
        seguridad: { acceso: 'publica' },
      };
    }

    // 2.2 Cuenta (/api/v1/cuenta/*) -> usuarios (perfil) y reservas (reservas*, consultar-reserva)
    if (sub === '/cuenta/perfil') {
      return {
        servicio: 'usuarios',
        plantilla: '/api/v1/cuenta/perfil',
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['cliente', 'administrador', 'superadmin'] },
      };
    }
    if (sub === '/cuenta/consultar-reserva' && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v1/cuenta/consultar-reserva',
        seguridad: { acceso: 'publica' },
      };
    }
    if (sub === '/cuenta/reservas' || sub.startsWith('/cuenta/reservas/')) {
      return {
        servicio: 'reservas',
        plantilla: sub === '/cuenta/reservas' ? '/api/v1/cuenta/reservas' : '/api/v1/cuenta/reservas/:localizador',
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['cliente', 'administrador', 'superadmin'] },
      };
    }

    // 2.3 Administración (/api/v1/admin/*)
    // - /api/v1/admin/usuarios* -> usuarios (solo superadmin)
    if (sub === '/admin/usuarios' || sub.startsWith('/admin/usuarios/')) {
      return {
        servicio: 'usuarios',
        plantilla: plantillaDeRuta(pathname),
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['superadmin'] },
      };
    }

    // - /api/v1/admin/reservas* -> reservas (administrador, superadmin)
    if (sub === '/admin/reservas' || sub.startsWith('/admin/reservas/')) {
      return {
        servicio: 'reservas',
        plantilla: plantillaDeRuta(pathname),
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['administrador', 'superadmin'] },
      };
    }

    // - /api/v1/admin/planes*
    //   y /api/v1/admin/habitaciones/:id/(disponibilidad|planes|restricciones)* -> disponibilidad
    if (
      sub === '/admin/planes' ||
      sub.startsWith('/admin/planes/') ||
      /^\/admin\/habitaciones\/[^/]+\/(disponibilidad|planes|restricciones)(\/|$)/.test(sub)
    ) {
      return {
        servicio: 'disponibilidad',
        plantilla: plantillaDeRuta(pathname),
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['administrador', 'superadmin'] },
      };
    }

    // - /api/v1/admin/stock-outbox* -> disponibilidad (solo superadmin, como en el controlador)
    if (sub === '/admin/stock-outbox' || sub.startsWith('/admin/stock-outbox/')) {
      return {
        servicio: 'disponibilidad',
        plantilla: plantillaDeRuta(pathname),
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['superadmin'] },
      };
    }

    // - /api/v1/admin/alojamientos*, /api/v1/admin/ciudades*, /api/v1/admin/habitaciones* -> catalogo
    if (
      sub === '/admin/alojamientos' ||
      sub.startsWith('/admin/alojamientos/') ||
      sub === '/admin/ciudades' ||
      sub.startsWith('/admin/ciudades/') ||
      sub === '/admin/habitaciones' ||
      sub.startsWith('/admin/habitaciones/')
    ) {
      return {
        servicio: 'catalogo',
        plantilla: plantillaDeRuta(pathname),
        seguridad: { acceso: 'v1_protegida', rolesPermitidos: ['administrador', 'superadmin'] },
      };
    }

    // 2.4 Rutas públicas y de órdenes del contrato v1
    // - /api/v1/search, availability, bulk-availability, details*, chains, constants y reviews* -> catalogo
    if (
      sub === '/search' ||
      sub === '/availability' ||
      sub === '/bulk-availability' ||
      sub === '/details' ||
      sub === '/chains' ||
      sub === '/constants' ||
      sub === '/reviews' ||
      sub === '/reviews/scores'
    ) {
      return {
        servicio: 'catalogo',
        plantilla: `/api/v1${sub}`,
        seguridad: { acceso: 'publica' },
      };
    }
    if (sub === '/details/changes') {
      return {
        servicio: 'catalogo',
        plantilla: '/api/v1/details/changes',
        seguridad: { acceso: 'publica', scopeOpcional: 'alojamientos:read' },
      };
    }

    // - /api/v1/orders/* y /api/v1/webhooks* -> reservas
    if (sub === '/orders/preview' && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v1/orders/preview',
        seguridad: { acceso: 'publica', scopeOpcional: 'alojamientos:read' },
      };
    }
    if (sub === '/orders/create' && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v1/orders/create',
        seguridad: { acceso: 'publica', scopeOpcional: 'alojamientos:book' },
      };
    }
    if (/^\/orders\/[^/]+$/.test(sub) && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v1/orders/:id',
        seguridad: { acceso: 'publica', scopeOpcional: 'alojamientos:read' },
      };
    }
    if (/^\/orders\/[^/]+\/modify$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v1/orders/:id/modify',
        seguridad: { acceso: 'publica', scopeOpcional: 'alojamientos:book' },
      };
    }
    if (/^\/orders\/[^/]+\/cancel$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v1/orders/:id/cancel',
        seguridad: { acceso: 'publica', scopeOpcional: 'alojamientos:cancel' },
      };
    }
    if (sub.startsWith('/orders/')) {
      return {
        servicio: 'reservas',
        plantilla: plantillaDeRuta(pathname),
        seguridad: { acceso: 'publica' },
      };
    }
    if (sub === '/webhooks' || sub.startsWith('/webhooks/')) {
      return {
        servicio: 'reservas',
        plantilla: sub === '/webhooks' ? '/api/v1/webhooks' : '/api/v1/webhooks/:id',
        seguridad: { acceso: 'publica', scopeOpcional: 'alojamientos:webhooks' },
      };
    }

    return null;
  }

  // ── 3. Espacio /api/v2 (Booking) ──
  if (pathname === '/api/v2/alojamientos' || pathname.startsWith('/api/v2/alojamientos/')) {
    const sub = pathname.slice('/api/v2/alojamientos'.length); // '' o empieza con '/'

    // 3.1 Rutas estáticas de /api/v2/alojamientos (precedencia sobre /alojamientos/{id})
    if (sub === '' && m === 'GET') {
      return { servicio: 'catalogo', plantilla: '/api/v2/alojamientos', seguridad: { acceso: 'publica' } };
    }
    if (sub === '/health' && m === 'GET') {
      return { servicio: 'catalogo', plantilla: '/api/v2/alojamientos/health', seguridad: { acceso: 'publica' } };
    }
    if (sub === '/categorias' && m === 'GET') {
      return { servicio: 'catalogo', plantilla: '/api/v2/alojamientos/categorias', seguridad: { acceso: 'publica' } };
    }
    if (sub === '/tipos' && m === 'GET') {
      return { servicio: 'catalogo', plantilla: '/api/v2/alojamientos/tipos', seguridad: { acceso: 'publica' } };
    }
    if (sub === '/search' && m === 'POST') {
      return { servicio: 'catalogo', plantilla: '/api/v2/alojamientos/search', seguridad: { acceso: 'publica' } };
    }
    if (sub === '/availability' && m === 'POST') {
      return { servicio: 'catalogo', plantilla: '/api/v2/alojamientos/availability', seguridad: { acceso: 'publica' } };
    }
    if (sub === '/eventos' && m === 'GET') {
      return {
        servicio: 'event-bus',
        plantilla: '/api/v2/alojamientos/eventos',
        seguridad: { acceso: 'publica' },
      };
    }

    // 3.2 Promociones B2B -> reservas
    if (sub === '/promociones/contrato' && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/promociones/contrato',
        seguridad: { acceso: 'publica' },
      };
    }
    if (sub === '/promociones/contrato' && m === 'PUT') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/promociones/contrato',
        seguridad: { acceso: 'publica' },
      };
    }

    // 3.3 Órdenes y sus alias deprecados -> reservas
    if (sub === '/orders/create' && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/orders/create',
        seguridad: { acceso: 'publica' },
      };
    }
    if (sub === '/reservas' && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservas',
        seguridad: { acceso: 'publica' },
      };
    }
    if (sub === '/orders' && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/orders',
        seguridad: { acceso: 'publica' },
      };
    }
    if (sub === '/reservations' && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservations',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/orders\/[^/]+$/.test(sub) && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/orders/:orderId',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/reservas\/[^/]+$/.test(sub) && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservas/:id',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/reservations\/[^/]+$/.test(sub) && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservations/:reservationId',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/orders\/[^/]+\/cancel$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/orders/:orderId/cancel',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/reservas\/[^/]+\/cancel$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservas/:id/cancel',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/reservations\/[^/]+\/cancel$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservations/:reservationId/cancel',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/orders\/[^/]+\/check-in$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/orders/:orderId/check-in',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/reservas\/[^/]+\/checkin$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservas/:id/checkin',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/reservations\/[^/]+\/checkin$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservations/:reservationId/checkin',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/orders\/[^/]+\/early-checkin$/.test(sub) && m === 'PUT') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/orders/:orderId/early-checkin',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/orders\/[^/]+\/checkout$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/orders/:orderId/checkout',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/reservas\/[^/]+\/checkout$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservas/:id/checkout',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/reservations\/[^/]+\/checkout$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/reservations/:reservationId/checkout',
        seguridad: { acceso: 'publica' },
      };
    }

    // 3.4 Rutas bajo /api/v2/alojamientos/{id}
    if (/^\/[^/]+\/inventario$/.test(sub) && m === 'GET') {
      return {
        servicio: 'disponibilidad',
        plantilla: '/api/v2/alojamientos/:id/inventario',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+\/reservations$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/:id/reservations',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+\/resenas$/.test(sub) && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/:id/resenas',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+\/reviews$/.test(sub) && m === 'GET') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/:id/reviews',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+\/resenas$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/:id/resenas',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+\/reviews$/.test(sub) && m === 'POST') {
      return {
        servicio: 'reservas',
        plantilla: '/api/v2/alojamientos/:id/reviews',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+\/habitaciones$/.test(sub) && m === 'GET') {
      return {
        servicio: 'catalogo',
        plantilla: '/api/v2/alojamientos/:id/habitaciones',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+\/availability$/.test(sub) && m === 'GET') {
      return {
        servicio: 'catalogo',
        plantilla: '/api/v2/alojamientos/:id/availability',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+\/disponibilidad$/.test(sub) && m === 'GET') {
      return {
        servicio: 'catalogo',
        plantilla: '/api/v2/alojamientos/:id/disponibilidad',
        seguridad: { acceso: 'publica' },
      };
    }
    if (/^\/[^/]+$/.test(sub) && m === 'GET') {
      return {
        servicio: 'catalogo',
        plantilla: '/api/v2/alojamientos/:id',
        seguridad: { acceso: 'publica' },
      };
    }
  }

  // ── 3.5 Clientes v2 (/api/v2/clientes) -> usuarios ──
  if (pathname === '/api/v2/clientes' || pathname.startsWith('/api/v2/clientes/')) {
    const sub = pathname.slice('/api/v2/clientes'.length);
    if ((sub === '' || sub === '/') && (m === 'GET' || m === 'POST')) {
      return {
        servicio: 'usuarios',
        plantilla: '/api/v2/clientes',
        seguridad: { acceso: 'publica' },
      };
    }
  }

  return null;
}

async function leerCuerpoCrudo(req: Request): Promise<Buffer> {
  if (Buffer.isBuffer(req.body)) return req.body;
  if (typeof req.body === 'string') return Buffer.from(req.body, 'utf8');
  if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
    return Buffer.from(JSON.stringify(req.body), 'utf8');
  }
  if (req.readableEnded) return Buffer.alloc(0);

  return new Promise<Buffer>((resolve, reject) => {
    const trozos: Buffer[] = [];
    req.on('data', (chunk: Buffer | string) => {
      trozos.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on('end', () => resolve(Buffer.concat(trozos)));
    req.on('error', reject);
  });
}

@Injectable()
export class EnrutadorGatewayService {
  constructor(private readonly seguridadJwt: SeguridadJwtGatewayService) {}

  async reenviarPeticion(req: PeticionGateway, res: Response): Promise<void> {
    const urlOriginal = req.originalUrl || req.url || '/';
    const destino = resolverDestinoRuta(req.method, urlOriginal);
    if (!destino) {
      throw new GatewayProblemException(404, 'NOT_FOUND', `No existe la ruta ${req.method} ${urlOriginal.split('?')[0]}`);
    }

    req.plantillaRuta = destino.plantilla;

    // Si aún no hay clave de verificación JWT cargada localmente y la ruta requiere verificar un Bearer,
    // intenta obtener la clave pública RS256 de `usuarios` (D3).
    if (
      req.headers.authorization &&
      this.seguridadJwt.resolverVerificadorUi().modo === 'ninguno' &&
      !process.env.OAUTH_JWT_SECRET &&
      !process.env.OAUTH_JWT_PUBLIC_KEY
    ) {
      await this.intentarCargarClavePublicaDeUsuarios();
    }

    // Validación JWT RS256, roles y scopes antes de enrutar
    await this.seguridadJwt.verificarAccesoRuta(req, destino.seguridad);

    const cuerpo = ['GET', 'HEAD'].includes(req.method.toUpperCase()) ? Buffer.alloc(0) : await leerCuerpoCrudo(req);

    // Si en una ruta con cuerpo JSON el cliente envió un JSON mal formado, devolvemos 400 VALIDATION_FAILED en ProblemDetails
    const contentTypeEntrada = (req.header('content-type') ?? '').toLowerCase();
    if (cuerpo.length > 0 && contentTypeEntrada.includes('application/json')) {
      try {
        JSON.parse(cuerpo.toString('utf8'));
      } catch {
        throw new GatewayProblemException(400, 'VALIDATION_FAILED', 'El cuerpo de la petición no es JSON válido.');
      }
    }

    const cabecerasEnvio: Record<string, string> = {};
    for (const nombre of CABECERAS_ENTRADA_REENVIADAS) {
      const valor = req.header(nombre);
      if (valor !== undefined) {
        cabecerasEnvio[nombre] = valor;
      }
    }
    if (req.correlationId) {
      cabecerasEnvio['x-correlation-id'] = req.correlationId;
    }

    const timeoutMs = Number(process.env.GATEWAY_TIMEOUT_MS) > 0 ? Number(process.env.GATEWAY_TIMEOUT_MS) : 10_000;
    const baseServicio = resolverUrlServicio(destino.servicio);
    const urlDestino = `${baseServicio}${urlOriginal}`;

    let respuesta: globalThis.Response;
    try {
      respuesta = await fetch(urlDestino, {
        method: req.method,
        headers: cabecerasEnvio,
        body: cuerpo.length > 0 ? new Uint8Array(cuerpo) : undefined,
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });

      // Si /api/v2/alojamientos/eventos se enrutó a event-bus (3005) y ese proceso solo expone /health,
      // hace fallback automático al servicio disponibilidad/comun que sirve la tabla comun.feed_eventos.
      if (
        destino.servicio === 'event-bus' &&
        respuesta.status === 404 &&
        !process.env.FEED_URL &&
        !process.env.COMUN_URL
      ) {
        const baseDisponibilidad = resolverUrlServicio('disponibilidad');
        if (baseDisponibilidad !== baseServicio) {
          respuesta = await fetch(`${baseDisponibilidad}${urlOriginal}`, {
            method: req.method,
            headers: cabecerasEnvio,
            body: cuerpo.length > 0 ? new Uint8Array(cuerpo) : undefined,
            redirect: 'manual',
            signal: AbortSignal.timeout(timeoutMs),
          });
        }
      }
    } catch (error) {
      const nombre = (error as Error)?.name ?? '';
      if (nombre === 'TimeoutError' || nombre === 'AbortError') {
        throw new GatewayProblemException(
          504,
          'GATEWAY_TIMEOUT',
          `El servicio ${destino.servicio} no respondió a tiempo.`,
        );
      }
      throw new GatewayProblemException(
        502,
        'INTERNAL_ERROR',
        `No se pudo conectar con el servicio ${destino.servicio}.`,
      );
    }

    const bufferRespuesta = Buffer.from(await respuesta.arrayBuffer());
    const contentTypeRespuesta = respuesta.headers.get('content-type') ?? '';

    const cabecerasSalto = new Set(['connection', 'transfer-encoding', 'keep-alive']);
    respuesta.headers.forEach((valor, clave) => {
      if (!cabecerasSalto.has(clave.toLowerCase())) {
        res.setHeader(clave, valor);
      }
    });
    if (req.correlationId && !res.getHeader('x-correlation-id')) {
      res.setHeader('X-Correlation-ID', req.correlationId);
    }

    res.status(respuesta.status);
    if (contentTypeRespuesta && !res.getHeader('content-type')) {
      res.type(contentTypeRespuesta);
    }
    res.send(bufferRespuesta);
  }

  private async intentarCargarClavePublicaDeUsuarios(): Promise<void> {
    try {
      const baseUsuarios = resolverUrlServicio('usuarios');
      const r = await fetch(`${baseUsuarios}/api/v1/interno/usuarios/clave-publica`, {
        signal: AbortSignal.timeout(1500),
      });
      if (!r.ok) return;
      const datos = (await r.json()) as { publicKey?: string | null };
      if (typeof datos?.publicKey === 'string' && datos.publicKey.trim()) {
        this.seguridadJwt.fijarClavePublicaRemota(datos.publicKey);
      }
    } catch {
      // Si el servicio usuarios no está disponible o no tiene clave RSA, continuará con el flujo normal (401).
    }
  }
}

function esRutaGraphql(url: string): boolean {
  const sinQuery = url.split('?')[0];
  return sinQuery === '/graphql' || sinQuery.startsWith('/graphql/');
}

