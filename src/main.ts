import './registro-rutas';
import { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { GatewayAppModule } from './app.module';
import { LoggerGateway, middlewareCorrelacionGateway } from './correlacion-y-logs';
import { GatewayProblemFilter } from './problemas';

export async function crearAppGateway(opciones: { limitePorMinuto?: number } = {}): Promise<INestApplication> {
  // bodyParser: false para reenviar el cuerpo crudo intacto a los microservicios y responder ProblemDetails ante JSON mal formado
  const app = await NestFactory.create(GatewayAppModule, {
    logger: new LoggerGateway('gateway-esb'),
    bodyParser: false,
  });

  const expressApp = app.getHttpAdapter().getInstance();
  if (typeof expressApp?.disable === 'function') {
    expressApp.disable('x-powered-by');
  }

  app.use(middlewareCorrelacionGateway(opciones));
  app.useGlobalFilters(new GatewayProblemFilter());

  const origenes = (process.env.CORS_ORIGIN ?? 'http://localhost:5173')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  app.enableCors({
    origin: origenes,
    credentials: true,
    exposedHeaders: [
      'X-Correlation-ID',
      'ETag',
      'Idempotent-Replayed',
      'Retry-After',
      'RateLimit-Limit',
      'RateLimit-Remaining',
      'RateLimit-Reset',
      'Location',
    ],
  });

  return app;
}

async function bootstrap(): Promise<void> {
  const app = await crearAppGateway();
  const port = Number(process.env.PORT_GATEWAY || process.env.PORT || 3000);
  await app.listen(port);
}

if (require.main === module) {
  void bootstrap();
}

