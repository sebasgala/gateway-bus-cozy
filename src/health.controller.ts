import { createConnection } from 'net';
import { Controller, Get, HttpStatus, Req, Res, VERSION_NEUTRAL } from '@nestjs/common';
import { Response } from 'express';
import { PeticionGateway } from './correlacion-y-logs';
import { resolverUrlServicio } from './enrutador.service';

export type EstadoComponenteSalud = 'up' | 'down';

export interface RespuestaSaludGateway {
  status: 'ok' | 'error';
  modulo: 'gateway-esb';
  usuarios: EstadoComponenteSalud;
  catalogo: EstadoComponenteSalud;
  disponibilidad: EstadoComponenteSalud;
  reservas: EstadoComponenteSalud;
  rabbitmq: EstadoComponenteSalud;
  servicios: {
    usuarios: { status: EstadoComponenteSalud };
    catalogo: { status: EstadoComponenteSalud };
    disponibilidad: { status: EstadoComponenteSalud };
    reservas: { status: EstadoComponenteSalud };
    rabbitmq: { status: EstadoComponenteSalud };
  };
  uptime: number;
}

const SERVICIOS_DOMINIO = ['usuarios', 'catalogo', 'disponibilidad', 'reservas'] as const;
type ServicioDominio = (typeof SERVICIOS_DOMINIO)[number];

async function comprobarSaludHttp(
  urlBase: string,
  correlationId?: string,
  timeoutMs = 2000,
): Promise<EstadoComponenteSalud> {
  const cabeceras: Record<string, string> = {};
  if (correlationId) {
    cabeceras['x-correlation-id'] = correlationId;
  }

  for (const ruta of ['/health', '/api/v1/health']) {
    try {
      const r = await fetch(`${urlBase}${ruta}`, {
        headers: cabeceras,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (r.status === 404 && ruta === '/health') {
        continue;
      }
      if (!r.ok) return 'down';
      const datos = (await r.json().catch(() => null)) as Record<string, unknown> | null;
      if (datos && datos.status === 'ok') return 'up';
      return 'down';
    } catch {
      return 'down';
    }
  }
  return 'down';
}

function probarPuertoTcp(host: string, port: number, timeoutMs: number): Promise<EstadoComponenteSalud> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    let resuelto = false;
    const finalizar = (estado: EstadoComponenteSalud) => {
      if (resuelto) return;
      resuelto = true;
      socket.destroy();
      resolve(estado);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finalizar('up'));
    socket.once('timeout', () => finalizar('down'));
    socket.once('error', () => finalizar('down'));
  });
}

async function comprobarSaludRabbitMq(
  correlationId?: string,
  timeoutMs = 2000,
  env: NodeJS.ProcessEnv = process.env,
): Promise<EstadoComponenteSalud> {
  const urlEventBus = (env.EVENT_BUS_URL?.trim() || 'http://localhost:3005').replace(/\/+$/, '');
  const cabeceras: Record<string, string> = {};
  if (correlationId) {
    cabeceras['x-correlation-id'] = correlationId;
  }

  try {
    const r = await fetch(`${urlEventBus}/health`, {
      headers: cabeceras,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (r.ok) {
      const datos = (await r.json().catch(() => null)) as Record<string, unknown> | null;
      if (datos && (datos.rabbitmq === 'up' || datos.status === 'ok')) {
        return 'up';
      }
    }
  } catch {
    // Si event-bus no responde por HTTP, probamos conexión TCP directa a RABBITMQ_URL si está definida
  }

  const rabbitUrl = env.RABBITMQ_URL?.trim();
  if (!rabbitUrl) return 'down';
  try {
    const parsed = new URL(rabbitUrl);
    const host = parsed.hostname || 'localhost';
    const port = parsed.port ? Number(parsed.port) : parsed.protocol === 'amqps:' ? 5671 : 5672;
    return await probarPuertoTcp(host, port, timeoutMs);
  } catch {
    return 'down';
  }
}

export async function obtenerSaludAgregadaGateway(
  correlationId?: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<RespuestaSaludGateway> {
  const timeoutMs = Number(env.HEALTH_TIMEOUT_MS) > 0 ? Number(env.HEALTH_TIMEOUT_MS) : 2000;

  const [usuarios, catalogo, disponibilidad, reservas, rabbitmq] = await Promise.all([
    ...SERVICIOS_DOMINIO.map((s: ServicioDominio) =>
      comprobarSaludHttp(resolverUrlServicio(s, env), correlationId, timeoutMs),
    ),
    comprobarSaludRabbitMq(correlationId, timeoutMs, env),
  ]);

  const todosUp =
    usuarios === 'up' &&
    catalogo === 'up' &&
    disponibilidad === 'up' &&
    reservas === 'up' &&
    rabbitmq === 'up';

  return {
    status: todosUp ? 'ok' : 'error',
    modulo: 'gateway-esb',
    usuarios,
    catalogo,
    disponibilidad,
    reservas,
    rabbitmq,
    servicios: {
      usuarios: { status: usuarios },
      catalogo: { status: catalogo },
      disponibilidad: { status: disponibilidad },
      reservas: { status: reservas },
      rabbitmq: { status: rabbitmq },
    },
    uptime: process.uptime(),
  };
}

@Controller({ path: 'health', version: VERSION_NEUTRAL })
export class HealthController {
  @Get()
  async check(@Req() req: PeticionGateway, @Res({ passthrough: true }) res: Response): Promise<RespuestaSaludGateway> {
    req.plantillaRuta = '/health';
    const resultado = await obtenerSaludAgregadaGateway(req.correlationId);
    res.status(resultado.status === 'ok' ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE);
    return resultado;
  }
}

@Controller({ path: 'api/v1/health', version: VERSION_NEUTRAL })
export class HealthV1Controller {
  @Get()
  async check(@Req() req: PeticionGateway, @Res({ passthrough: true }) res: Response): Promise<RespuestaSaludGateway> {
    req.plantillaRuta = '/api/v1/health';
    const resultado = await obtenerSaludAgregadaGateway(req.correlationId);
    res.status(resultado.status === 'ok' ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE);
    return resultado;
  }
}

