import './registro-rutas';
import { strict as assert } from 'node:assert';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { describe, it } from 'node:test';
import { JwtService } from '@nestjs/jwt';
import { NextFunction, Response } from 'express';
import { middlewareCorrelacionGateway, PeticionGateway } from './correlacion-y-logs';
import { EnrutadorGatewayService, resolverDestinoRuta } from './enrutador.service';
import { HealthController, obtenerSaludAgregadaGateway } from './health.controller';
import { GatewayProblemException, responderProblemaGateway } from './problemas';
import { REQUISITOS_V2_GATEWAY, SeguridadJwtGatewayService } from './seguridad-jwt.service';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const { privateKey: otraPrivada } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function crearParHttpSimulado(opciones: {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
}) {
  const cabecerasEntrada = Object.fromEntries(
    Object.entries(opciones.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
  );

  const req = Object.assign(new EventEmitter(), {
    method: opciones.method,
    url: opciones.url,
    originalUrl: opciones.url,
    headers: cabecerasEntrada,
    body:
      opciones.body === undefined
        ? undefined
        : typeof opciones.body === 'string'
          ? Buffer.from(opciones.body, 'utf8')
          : Buffer.from(JSON.stringify(opciones.body), 'utf8'),
    readableEnded: true,
    ip: '127.0.0.1',
    secure: false,
    header(nombre: string): string | undefined {
      return cabecerasEntrada[nombre.toLowerCase()];
    },
  }) as unknown as PeticionGateway;

  const cabecerasSalida = new Map<string, string>();
  let codigoEstado = 200;
  let cuerpoSalida = '';

  const res = Object.assign(new EventEmitter(), {
    statusCode: 200,
    headersSent: false,
    setHeader(nombre: string, valor: string) {
      cabecerasSalida.set(nombre.toLowerCase(), String(valor));
      return this;
    },
    getHeader(nombre: string) {
      return cabecerasSalida.get(nombre.toLowerCase());
    },
    status(codigo: number) {
      codigoEstado = codigo;
      this.statusCode = codigo;
      return this;
    },
    type(tipo: string) {
      cabecerasSalida.set('content-type', tipo);
      return this;
    },
    json(obj: unknown) {
      this.headersSent = true;
      if (!cabecerasSalida.has('content-type')) {
        cabecerasSalida.set('content-type', 'application/json');
      }
      cuerpoSalida = JSON.stringify(obj);
      this.emit('finish');
      return this;
    },
    send(datos: Buffer | string) {
      this.headersSent = true;
      cuerpoSalida = Buffer.isBuffer(datos) ? datos.toString('utf8') : String(datos);
      this.emit('finish');
      return this;
    },
  }) as unknown as Response;

  return {
    req,
    res,
    obtenerRespuesta: () => ({
      status: codigoEstado,
      headers: cabecerasSalida,
      texto: cuerpoSalida,
      json: cuerpoSalida ? (JSON.parse(cuerpoSalida) as Record<string, unknown>) : null,
    }),
  };
}

describe('gateway-esb (fase 9.4)', () => {
  it('enruta todas las familias de rutas públicas e internas al servicio correspondiente (§5)', () => {
    assert.equal(resolverDestinoRuta('POST', '/graphql')?.servicio, 'graphql');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/auth/login')?.servicio, 'usuarios');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/auth/registro')?.servicio, 'usuarios');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/auth/me')?.servicio, 'usuarios');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/cuenta/perfil')?.servicio, 'usuarios');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/cuenta/cambiar-contrasena'), null);
    assert.equal(resolverDestinoRuta('POST', '/api/v1/cuenta/cerrar-sesion'), null);
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/usuarios')?.servicio, 'usuarios');

    assert.equal(resolverDestinoRuta('POST', '/api/v1/search')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/availability')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/bulk-availability')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/details')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/details/changes')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/chains')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/constants')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/reviews')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/alojamientos')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/ciudades')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/habitaciones/abc')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/cadenas'), null);
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/tipos-habitacion'), null);

    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/habitaciones/abc/disponibilidad')?.servicio, 'disponibilidad');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/habitaciones/abc/planes')?.servicio, 'disponibilidad');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/habitaciones/abc/restricciones')?.servicio, 'disponibilidad');
    assert.equal(resolverDestinoRuta('PATCH', '/api/v1/admin/planes/p1')?.servicio, 'disponibilidad');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/disponibilidad'), null);
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/bloqueos'), null);
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/precios'), null);
    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/stock-outbox')?.servicio, 'disponibilidad');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/admin/stock-outbox/limpiar')?.servicio, 'disponibilidad');
    assert.deepEqual(resolverDestinoRuta('GET', '/api/v1/admin/stock-outbox')?.seguridad, {
      acceso: 'v1_protegida',
      rolesPermitidos: ['superadmin'],
    });

    assert.equal(resolverDestinoRuta('GET', '/api/v1/admin/reservas')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/cuenta/reservas')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/cuenta/consultar-reserva')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/orders/preview')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('POST', '/api/v1/orders/create')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('GET', '/api/v1/webhooks')?.servicio, 'reservas');

    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/eventos')?.servicio, 'event-bus');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/HTL-EC-0001/inventario')?.servicio, 'disponibilidad');
    assert.equal(resolverDestinoRuta('POST', '/api/v2/alojamientos/orders/create')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/orders/ORD-HTL-123')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/promociones/contrato')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/HTL-EC-0001/resenas')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('POST', '/api/v2/alojamientos/HTL-EC-0001/reservations')?.servicio, 'reservas');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/health')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v2/alojamientos/search')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('POST', '/api/v2/alojamientos/availability')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/categorias')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/HTL-EC-0001')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/HTL-EC-0001/habitaciones')?.servicio, 'catalogo');
    assert.equal(resolverDestinoRuta('GET', '/api/v2/alojamientos/HTL-EC-0001/availability')?.servicio, 'catalogo');
  });

  it('valida JWT RS256 con la clave pública y verifica roles y scopes (D3)', async () => {
    const seguridad = new SeguridadJwtGatewayService();
    const firmadorRsa = new JwtService({
      privateKey,
      signOptions: { algorithm: 'RS256', expiresIn: '10m' },
    });
    const envRsa: NodeJS.ProcessEnv = { JWT_PUBLIC_KEY: publicKey };
    const idUsuario = randomUUID();

    // 1. Token de usuario válido firmado con RS256
    const tokenCliente = await firmadorRsa.signAsync({
      sub: idUsuario,
      rol: 'cliente',
      estado: 'activo',
    });
    const principalCliente = await seguridad.verificarTokenBearer(`Bearer ${tokenCliente}`, undefined, envRsa);
    assert.equal(principalCliente.usuarioId, idUsuario);
    assert.equal(principalCliente.rolUsuario, 'cliente');
    assert.equal(principalCliente.rolV2, 'CLIENTE');

    // 2. Verificación de roles: cliente no puede entrar a ruta de superadmin
    assert.throws(
      () => seguridad.exigirRolUsuario(principalCliente, ['superadmin']),
      (err: GatewayProblemException) => err.estado === 403 && err.codigo === 'FORBIDDEN',
    );

    // 3. Token firmado con otra clave privada RSA o con HS256 es rechazado (401 UNAUTHORIZED)
    const firmadorOtraRsa = new JwtService({
      privateKey: otraPrivada,
      signOptions: { algorithm: 'RS256', expiresIn: '10m' },
    });
    const tokenOtraClave = await firmadorOtraRsa.signAsync({
      sub: idUsuario,
      rol: 'cliente',
      estado: 'activo',
    });
    await assert.rejects(
      () => seguridad.verificarTokenBearer(`Bearer ${tokenOtraClave}`, undefined, envRsa),
      (err: GatewayProblemException) => err.estado === 401 && err.codigo === 'UNAUTHORIZED',
    );

    const tokenHs256 = await new JwtService({ secret: 'secreto-hs256-de-mas-de-32-caracteres-1234' }).signAsync(
      { sub: idUsuario, rol: 'cliente', estado: 'activo' },
      { algorithm: 'HS256' },
    );
    await assert.rejects(
      () => seguridad.verificarTokenBearer(`Bearer ${tokenHs256}`, undefined, envRsa),
      (err: GatewayProblemException) => err.estado === 401 && err.codigo === 'UNAUTHORIZED',
    );

    // 4. Verificación de scopes (alojamientos:book, alojamientos:read, alojamientos:cancel)
    const tokenSoloLectura = await firmadorRsa.signAsync({
      sub: 'booking-client',
      scope: 'alojamientos:read',
    });
    const principalLectura = await seguridad.verificarTokenBearer(`Bearer ${tokenSoloLectura}`, undefined, envRsa);
    assert.equal(principalLectura.via, 'oauth');
    assert.deepEqual(principalLectura.scopes, ['alojamientos:read']);

    // Scope válido para getOrder (alojamientos:read)
    assert.doesNotThrow(() => seguridad.autorizarOperacionV2(principalLectura, REQUISITOS_V2_GATEWAY.getOrder));

    // Scope insuficiente para createOrder (exige alojamientos:book) -> 403 INSUFFICIENT_SCOPE
    assert.throws(
      () => seguridad.autorizarOperacionV2(principalLectura, REQUISITOS_V2_GATEWAY.createOrder),
      (err: GatewayProblemException) =>
        err.estado === 403 &&
        err.codigo === 'INSUFFICIENT_SCOPE' &&
        err.extras.scopes_requeridos?.[0] === 'alojamientos:book',
    );
  });

  it('enruta peticiones HTTP, propaga X-Correlation-ID, responde ProblemDetails con code y agrega /health', async () => {
    const fetchOriginal = globalThis.fetch;
    const recibidas: Array<{ url: string; method: string; correlacion?: string }> = [];

    const envAnterior = {
      USUARIOS_URL: process.env.USUARIOS_URL,
      CATALOGO_URL: process.env.CATALOGO_URL,
      DISPONIBILIDAD_URL: process.env.DISPONIBILIDAD_URL,
      RESERVAS_URL: process.env.RESERVAS_URL,
      EVENT_BUS_URL: process.env.EVENT_BUS_URL,
      JWT_PUBLIC_KEY: process.env.JWT_PUBLIC_KEY,
      V2_LOG_PETICIONES: process.env.V2_LOG_PETICIONES,
    };

    process.env.USUARIOS_URL = 'http://usuarios.interno:3001';
    process.env.CATALOGO_URL = 'http://catalogo.interno:3002';
    process.env.DISPONIBILIDAD_URL = 'http://disponibilidad.interno:3003';
    process.env.RESERVAS_URL = 'http://reservas.interno:3004';
    process.env.EVENT_BUS_URL = 'http://event-bus.interno:3005';
    process.env.JWT_PUBLIC_KEY = publicKey;
    process.env.V2_LOG_PETICIONES = 'false';

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<globalThis.Response> => {
      const url = String(input);
      const cabeceras = (init?.headers ?? {}) as Record<string, string>;
      const cid = cabeceras['x-correlation-id'];
      recibidas.push({ url, method: init?.method ?? 'GET', correlacion: cid });

      if (url.endsWith('/health')) {
        return new globalThis.Response(
          JSON.stringify({
            status: 'ok',
            ...(url.includes('event-bus') ? { rabbitmq: 'up' } : { db: 'up' }),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }

      if (url.endsWith('/api/v2/alojamientos/orders/create')) {
        return new globalThis.Response(
          JSON.stringify({ orderId: 'ORD-HTL-0001', status: 'CONFIRMED' }),
          {
            status: 201,
            headers: {
              'Content-Type': 'application/json',
              'X-Correlation-ID': cid ?? '',
              'Idempotent-Replayed': 'false',
            },
          },
        );
      }

      return new globalThis.Response(JSON.stringify({ ok: true, url }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'X-Correlation-ID': cid ?? '' },
      });
    }) as typeof fetch;

    const seguridad = new SeguridadJwtGatewayService();
    const enrutador = new EnrutadorGatewayService(seguridad);
    const healthController = new HealthController();
    const mw = middlewareCorrelacionGateway();

    const ejecutarPorGateway = async (opciones: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: unknown;
    }) => {
      const par = crearParHttpSimulado(opciones);
      await new Promise<void>((resolve) => {
        mw(par.req, par.res, (async () => {
          try {
            if (opciones.url === '/health') {
              const cuerpo = await healthController.check(par.req, par.res);
              par.res.json(cuerpo);
            } else {
              await enrutador.reenviarPeticion(par.req, par.res);
            }
          } catch (err) {
            if (err instanceof GatewayProblemException) {
              responderProblemaGateway(
                par.req,
                par.res,
                err.estado,
                err.codigo,
                err.detalle,
                err.extras,
                err.cabeceras,
              );
            } else {
              responderProblemaGateway(par.req, par.res, 500, 'INTERNAL_ERROR', 'Error interno');
            }
          }
          resolve();
        }) as unknown as NextFunction);
      });
      return par.obtenerRespuesta();
    };

    try {
      // 1. GET /health agregado combina usuarios, catalogo, disponibilidad, reservas y rabbitmq
      const resHealth = await ejecutarPorGateway({
        method: 'GET',
        url: '/health',
        headers: { 'X-Correlation-ID': 'corr-health-001' },
      });
      assert.equal(resHealth.status, 200);
      assert.equal(resHealth.headers.get('x-correlation-id'), 'corr-health-001');
      assert.equal(resHealth.json?.status, 'ok');
      assert.equal(resHealth.json?.usuarios, 'up');
      assert.equal(resHealth.json?.catalogo, 'up');
      assert.equal(resHealth.json?.disponibilidad, 'up');
      assert.equal(resHealth.json?.reservas, 'up');
      assert.equal(resHealth.json?.rabbitmq, 'up');

      // 2. Ruta protegida sin token -> 401 ProblemDetails (application/problem+json) con campo code
      const resSinToken = await ejecutarPorGateway({
        method: 'GET',
        url: '/api/v1/auth/me',
      });
      assert.equal(resSinToken.status, 401);
      assert.ok((resSinToken.headers.get('content-type') ?? '').includes('application/problem+json'));
      assert.equal(resSinToken.json?.code, 'UNAUTHORIZED');

      // 3. Ruta /api/v2/alojamientos/orders/create con token RS256 y scope alojamientos:book -> 201 en reservas y propaga X-Correlation-ID
      const firmadorRsa = new JwtService({
        privateKey,
        signOptions: { algorithm: 'RS256', expiresIn: '10m' },
      });
      const tokenBook = await firmadorRsa.signAsync({
        sub: 'booking-svc',
        scope: 'alojamientos:book alojamientos:read',
      });
      const resCrear = await ejecutarPorGateway({
        method: 'POST',
        url: '/api/v2/alojamientos/orders/create',
        headers: {
          Authorization: `Bearer ${tokenBook}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': randomUUID(),
          'X-Correlation-ID': 'corr-booking-999',
        },
        body: { alojamientoId: 'HTL-EC-0001' },
      });
      assert.equal(resCrear.status, 201);
      assert.equal(resCrear.headers.get('x-correlation-id'), 'corr-booking-999');
      assert.ok(
        recibidas.some(
          (r) =>
            r.url === 'http://reservas.interno:3004/api/v2/alojamientos/orders/create' &&
            r.correlacion === 'corr-booking-999',
        ),
      );

      // 4. /graphql con token inválido -> 401 UNAUTHORIZED en ProblemDetails (§9)
      const resGraphqlInvalido = await ejecutarPorGateway({
        method: 'POST',
        url: '/graphql',
        headers: {
          Authorization: 'Bearer token-invalido-1234',
          'Content-Type': 'application/json',
        },
        body: { query: '{ alojamientos { id } }' },
      });
      assert.equal(resGraphqlInvalido.status, 401);
      assert.ok((resGraphqlInvalido.headers.get('content-type') ?? '').includes('application/problem+json'));
      assert.equal(resGraphqlInvalido.json?.code, 'UNAUTHORIZED');

      // 5. Paso directo en /api/v2 y no reescritura de errores (§5): error de servicio pasa tal cual
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<globalThis.Response> => {
        const url = String(input);
        const headers = (init?.headers ?? {}) as Record<string, string>;
        if (url.endsWith('/api/v2/alojamientos/search')) {
          return new globalThis.Response(JSON.stringify({ errorPropioServicio: true }), {
            status: 422,
            headers: {
              'Content-Type': 'application/json',
              'X-Node-Id': headers['x-node-id'] ?? 'node-1',
            },
          });
        }
        return new globalThis.Response(JSON.stringify({ ok: true }), { status: 200 });
      }) as typeof fetch;

      const resErrorPassthrough = await ejecutarPorGateway({
        method: 'POST',
        url: '/api/v2/alojamientos/search',
        headers: {
          'Content-Type': 'application/json',
          'X-Node-Id': 'nodo-booking-01',
          'X-Prueba-Desfase-Ms': '50',
        },
        body: { query: 'test' },
      });
      assert.equal(resErrorPassthrough.status, 422);
      assert.equal(resErrorPassthrough.json?.errorPropioServicio, true);
      assert.equal(resErrorPassthrough.headers.get('x-node-id'), 'nodo-booking-01');

      // 6. Si un servicio cae, obtenerSaludAgregadaGateway devuelve status: 'error'
      globalThis.fetch = (async (input: RequestInfo | URL): Promise<globalThis.Response> => {
        const url = String(input);
        if (url.includes('reservas')) {
          return new globalThis.Response(JSON.stringify({ status: 'error' }), { status: 503 });
        }
        return new globalThis.Response(JSON.stringify({ status: 'ok', rabbitmq: 'up' }), { status: 200 });
      }) as typeof fetch;
      const saludDegradada = await obtenerSaludAgregadaGateway('corr-health-002');
      assert.equal(saludDegradada.status, 'error');
      assert.equal(saludDegradada.reservas, 'down');
      assert.equal(saludDegradada.usuarios, 'up');
    } finally {
      globalThis.fetch = fetchOriginal;
      for (const [k, v] of Object.entries(envAnterior)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });
});
