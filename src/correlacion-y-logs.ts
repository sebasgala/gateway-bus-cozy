import { AsyncLocalStorage } from 'async_hooks';
import { randomUUID } from 'crypto';
import { ConsoleLogger } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { esRutaV2, responderProblemaGateway } from './problemas';

export const CAMPOS_PII = [
  'nombre',
  'apellido',
  'nombreCompleto',
  'full_name',
  'identificacion',
  'titularIdentificacion',
  'document_id',
  'email',
  'correo',
  'telefono',
  'phone',
  'edad',
  'nacionalidad',
  'huespedTitular',
  'ocupantes',
  'huesped',
  'direccionFacturacion',
  'contacto_comercial',
] as const;

export const CAMPOS_SECRETOS = [
  'claveAccesoDigital',
  'password',
  'contrasena',
  'token',
  'accessToken',
  'authorization',
  'x-api-key',
  'cookie',
  'secret',
  'clave',
] as const;

const SENSIBLES = new Set<string>([...CAMPOS_PII, ...CAMPOS_SECRETOS].map((c) => c.toLowerCase()));
export const REDACTADO = '[REDACTADO]';

export function esCampoSensible(nombre: string): boolean {
  return SENSIBLES.has(nombre.toLowerCase());
}

export function redactar(valor: unknown, profundidad = 0): unknown {
  if (profundidad > 8 || valor === null || typeof valor !== 'object') return valor;
  if (Array.isArray(valor)) return valor.map((v) => redactar(v, profundidad + 1));
  return Object.fromEntries(
    Object.entries(valor as Record<string, unknown>).map(([k, v]) => [
      k,
      esCampoSensible(k) ? REDACTADO : redactar(v, profundidad + 1),
    ]),
  );
}

export interface ContextoCorrelacionGateway {
  correlationId: string;
  modulo: string;
}

export const contextoCorrelacion = new AsyncLocalStorage<ContextoCorrelacionGateway>();

export function correlacionActual(): string | undefined {
  return contextoCorrelacion.getStore()?.correlationId;
}

export class LoggerGateway extends ConsoleLogger {
  protected override formatContext(context: string): string {
    const cid = correlacionActual() ?? randomUUID();
    const base = context ? `${context} · cid=${cid}` : `cid=${cid}`;
    return super.formatContext(base);
  }
}

export const PATRON_CORRELACION = /^[A-Za-z0-9._:-]{4,64}$/;
const VENTANA_MS = 60_000;

export function registrarLogGateway(
  nivel: 'info' | 'warn' | 'error',
  evento: string,
  datos: Record<string, unknown> = {},
): void {
  const ctx = contextoCorrelacion.getStore();
  const correlationId =
    typeof datos.correlationId === 'string' && datos.correlationId
      ? datos.correlationId
      : (ctx?.correlationId ?? randomUUID());
  const enriquecidos = {
    modulo: 'gateway-esb',
    ...datos,
    correlationId,
  };
  const linea = JSON.stringify({
    ts: new Date().toISOString(),
    nivel,
    evento,
    ...(redactar(enriquecidos) as Record<string, unknown>),
  });
  (nivel === 'error' ? process.stderr : process.stdout).write(`${linea}\n`);
}

// Convierte una URL real en su plantilla de ruta sin identificadores reales ni cadena de consulta (LOPDP §7.1).
export function plantillaDeRuta(urlOriginal: string): string {
  const sinQuery = (urlOriginal || '/').split('?')[0];
  return sinQuery
    .replace(/\/(ORD-HTL-[A-Z0-9-]+|BK-HOTEL-[A-Z0-9-]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=\/|$)/g, '/:id')
    .replace(/\/(HTL-[A-Z0-9-]+)(?=\/|$)/g, '/:id')
    .replace(/\/\d+(?=\/|$)/g, '/:id');
}

export type PeticionGateway = Request & {
  correlationId?: string;
  plantillaRuta?: string;
  principalGateway?: { rol: string; via: string; usuarioId?: string };
};

export function middlewareCorrelacionGateway(opciones: { limitePorMinuto?: number } = {}) {
  const limite = opciones.limitePorMinuto ?? (Number(process.env.V2_LIMITE_POR_MINUTO) || 600);
  const activoLog = process.env.V2_LOG_PETICIONES?.trim().toLowerCase() !== 'false';
  const exigirHttps = process.env.V2_EXIGIR_HTTPS?.trim().toLowerCase() === 'true';
  const ventanas = new Map<string, { inicio: number; cuenta: number }>();

  setInterval(() => {
    const ahora = Date.now();
    for (const [ip, v] of ventanas) if (ahora - v.inicio >= VENTANA_MS) ventanas.delete(ip);
  }, VENTANA_MS).unref?.();

  return (req: PeticionGateway, res: Response, next: NextFunction) => {
    const url = req.originalUrl || req.url || '/';
    const enV2 = esRutaV2(url);
    const entrante = req.header('x-correlation-id');
    const valida = entrante === undefined || PATRON_CORRELACION.test(entrante);
    const correlacion = valida && entrante ? entrante : randomUUID();

    req.correlationId = correlacion;
    req.headers['x-correlation-id'] = correlacion;
    res.setHeader('X-Correlation-ID', correlacion);

    const inicio = process.hrtime.bigint();

    contextoCorrelacion.run({ correlationId: correlacion, modulo: 'gateway-esb' }, () => {
      if (activoLog) {
        res.on('finish', () => {
          registrarLogGateway('info', 'http', {
            metodo: req.method,
            ruta: req.plantillaRuta ?? plantillaDeRuta(url),
            estado: res.statusCode,
            ms: Math.round(Number(process.hrtime.bigint() - inicio) / 1e5) / 10,
            correlationId: req.correlationId ?? correlacion,
            ...(enV2
              ? {
                  credencial: req.principalGateway?.via ?? 'ninguna',
                  rol: req.principalGateway?.rol,
                }
              : {}),
          });
        });
      }

      if (enV2) {
        if (!valida) {
          responderProblemaGateway(
            req,
            res,
            400,
            'VALIDATION_FAILED',
            'La cabecera X-Correlation-ID no cumple el formato del contrato.',
            {
              invalid_params: [
                {
                  name: 'X-Correlation-ID',
                  reason:
                    'debe tener entre 4 y 64 caracteres de A-Z, a-z, 0-9, punto, guion, guion bajo o dos puntos',
                },
              ],
            },
          );
          return;
        }

        const ahora = Date.now();
        const clave = req.ip ?? 'desconocida';
        let ventana = ventanas.get(clave);
        if (!ventana || ahora - ventana.inicio >= VENTANA_MS) {
          ventana = { inicio: ahora, cuenta: 0 };
          ventanas.set(clave, ventana);
        }
        ventana.cuenta++;
        const reinicio = Math.max(1, Math.ceil((ventana.inicio + VENTANA_MS - ahora) / 1000));
        res.setHeader('RateLimit-Limit', String(limite));
        res.setHeader('RateLimit-Remaining', String(Math.max(0, limite - ventana.cuenta)));
        res.setHeader('RateLimit-Reset', String(reinicio));

        if (ventana.cuenta > limite) {
          responderProblemaGateway(
            req,
            res,
            429,
            'RATE_LIMITED',
            'Superaste el límite de peticiones. Espera antes de reintentar.',
            { retry_after_seconds: reinicio },
          );
          return;
        }

        if (req.secure) {
          res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        } else if (exigirHttps) {
          responderProblemaGateway(
            req,
            res,
            403,
            'FORBIDDEN',
            'Esta API solo se atiende por HTTPS (TLS 1.2 o superior).',
          );
          return;
        }
      }

      next();
    });
  };
}

