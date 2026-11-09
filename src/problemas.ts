import { ArgumentsHost, Catch, ExceptionFilter, HttpException } from '@nestjs/common';
import { Request, Response } from 'express';

export type CodigoErrorGateway =
  | 'VALIDATION_FAILED'
  | 'INVALID_DOCUMENT'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'ACCOUNT_PENDING'
  | 'ACCOUNT_SUSPENDED'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'OUT_OF_STOCK'
  | 'QUOTE_EXPIRED'
  | 'PRICE_MISMATCH'
  | 'IDEMPOTENCY_KEY_REUSED'
  | 'IDEMPOTENCY_IN_PROGRESS'
  | 'INVALID_STATE_TRANSITION'
  | 'CHECKIN_TIME_NOT_REACHED'
  | 'CAPACITY_EXCEEDED'
  | 'DISCOUNT_EXCEEDS_CONTRACT'
  | 'PROMOTIONS_NOT_ALLOWED'
  | 'RATE_LIMITED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'PROVIDER_DISABLED'
  | 'GATEWAY_TIMEOUT'
  | 'INTERNAL_ERROR'
  | 'RESTRICTION_VIOLATED'
  | 'UNSUPPORTED_CURRENCY'
  | 'INSUFFICIENT_SCOPE';

export interface ParametroInvalido {
  name: string;
  reason: string;
}

export interface ExtrasProblemaGateway {
  invalidParams?: ParametroInvalido[];
  invalid_params?: ParametroInvalido[];
  retry_after_seconds?: number;
  scopes_requeridos?: string[];
}

export class GatewayProblemException extends HttpException {
  readonly cabeceras: Record<string, string> = {};

  constructor(
    readonly estado: number,
    readonly codigo: CodigoErrorGateway,
    readonly detalle: string,
    readonly extras: ExtrasProblemaGateway = {},
  ) {
    super(detalle, estado);
  }
}

const TITULOS_V1: Record<number, string> = {
  400: 'Petición inválida',
  401: 'No autenticado',
  403: 'Prohibido',
  404: 'No encontrado',
  409: 'Conflicto',
  422: 'Petición no procesable',
  429: 'Demasiadas peticiones',
  500: 'Error interno del servidor',
  502: 'Puerta de enlace incorrecta',
  503: 'Servicio no disponible',
  504: 'Tiempo de espera agotado',
};

const TITULOS_V2: Record<number, string> = {
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  409: 'Conflict',
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
};

const CODIGO_POR_ESTADO: Record<number, CodigoErrorGateway> = {
  400: 'VALIDATION_FAILED',
  401: 'UNAUTHORIZED',
  403: 'FORBIDDEN',
  404: 'NOT_FOUND',
  409: 'CONFLICT',
  422: 'VALIDATION_FAILED',
  429: 'RATE_LIMITED',
  500: 'INTERNAL_ERROR',
  502: 'INTERNAL_ERROR',
  503: 'INTERNAL_ERROR',
  504: 'GATEWAY_TIMEOUT',
};

export function esRutaV2(url: string): boolean {
  return url === '/api/v2' || url.startsWith('/api/v2/') || url.startsWith('/api/v2?');
}

export function construirProblemaV2(
  estado: number,
  codigo: CodigoErrorGateway,
  detalle: string,
  instancia: string,
  correlacion?: string,
  extras: ExtrasProblemaGateway = {},
) {
  // En v2 el contrato usa el enum cerrado ErrorCode (ACCOUNT_PENDING / ACCOUNT_SUSPENDED se traducen a FORBIDDEN, RATE_LIMIT_EXCEEDED a RATE_LIMITED)
  const codigoV2: CodigoErrorGateway =
    codigo === 'ACCOUNT_PENDING' || codigo === 'ACCOUNT_SUSPENDED'
      ? 'FORBIDDEN'
      : codigo === 'RATE_LIMIT_EXCEEDED'
        ? 'RATE_LIMITED'
        : codigo;
  const invalidParams = extras.invalid_params ?? extras.invalidParams;
  return {
    type: `https://cozy.local/problems/${codigoV2.toLowerCase().replace(/_/g, '-')}`,
    title: TITULOS_V2[estado] ?? 'Error',
    status: estado,
    detail: detalle,
    instance: instancia.slice(0, 300),
    code: codigoV2,
    ...(correlacion && { correlation_id: correlacion }),
    timestamp: new Date().toISOString(),
    ...(invalidParams && invalidParams.length > 0 && { invalid_params: invalidParams }),
    ...(extras.retry_after_seconds !== undefined && { retry_after_seconds: extras.retry_after_seconds }),
    ...(extras.scopes_requeridos && { scopes_requeridos: extras.scopes_requeridos }),
  };
}

export function construirProblemaV1(
  estado: number,
  codigo: CodigoErrorGateway,
  detalle: string,
  extras: ExtrasProblemaGateway = {},
) {
  const invalidParams = extras.invalidParams ?? extras.invalid_params;
  return {
    type: 'about:blank',
    title: TITULOS_V1[estado] ?? 'Error',
    status: estado,
    detail: detalle,
    code: codigo,
    ...(invalidParams && invalidParams.length > 0 && { invalidParams }),
    ...(extras.scopes_requeridos && { scopes_requeridos: extras.scopes_requeridos }),
  };
}

export function responderProblemaGateway(
  req: Request & { correlationId?: string },
  res: Response,
  estado: number,
  codigo: CodigoErrorGateway,
  detalle: string,
  extras: ExtrasProblemaGateway = {},
  cabeceras: Record<string, string> = {},
): void {
  const url = req.originalUrl || req.url || '/';
  const instancia = url.split('?')[0];
  if (extras.retry_after_seconds !== undefined) {
    res.setHeader('Retry-After', String(extras.retry_after_seconds));
  }
  for (const [k, v] of Object.entries(cabeceras)) {
    res.setHeader(k, v);
  }

  if (esRutaV2(url)) {
    if (estado === 401) {
      res.setHeader('WWW-Authenticate', 'Bearer realm="alojamientos"');
    }
    const problema = construirProblemaV2(estado, codigo, detalle, instancia, req.correlationId, extras);
    res.status(estado).type('application/problem+json').json(problema);
    return;
  }

  const problema = construirProblemaV1(estado, codigo, detalle, extras);
  res.status(estado).type('application/problem+json').json(problema);
}

@Catch()
export class GatewayProblemFilter implements ExceptionFilter {
  catch(excepcion: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const req = ctx.getRequest<Request & { correlationId?: string }>();
    const res = ctx.getResponse<Response>();

    if (res.headersSent) return;

    if (excepcion instanceof GatewayProblemException) {
      responderProblemaGateway(
        req,
        res,
        excepcion.estado,
        excepcion.codigo,
        excepcion.detalle,
        excepcion.extras,
        excepcion.cabeceras,
      );
      return;
    }

    if (excepcion instanceof HttpException) {
      const estado = excepcion.getStatus();
      const cuerpo = excepcion.getResponse();
      const mensaje =
        typeof cuerpo === 'string'
          ? cuerpo
          : ((cuerpo as { message?: string | string[] }).message ?? excepcion.message);
      const detalle = Array.isArray(mensaje) ? mensaje.join('; ') : String(mensaje);
      const codigo =
        (excepcion as { code?: CodigoErrorGateway }).code ??
        CODIGO_POR_ESTADO[estado] ??
        (estado >= 500 ? 'INTERNAL_ERROR' : 'VALIDATION_FAILED');
      responderProblemaGateway(req, res, estado, codigo, detalle);
      return;
    }

    responderProblemaGateway(
      req,
      res,
      500,
      'INTERNAL_ERROR',
      'El gateway tuvo un problema inesperado.',
    );
  }
}

