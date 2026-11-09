import './registro-rutas';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_FILTER } from '@nestjs/core';
import { EnrutadorGatewayService } from './enrutador.service';
import { GatewayController } from './gateway.controller';
import { HealthController, HealthV1Controller } from './health.controller';
import { GatewayProblemFilter } from './problemas';
import { SeguridadJwtGatewayService } from './seguridad-jwt.service';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' })],
  // HealthController y HealthV1Controller van antes que el comodín GatewayController.
  controllers: [HealthController, HealthV1Controller, GatewayController],
  providers: [
    SeguridadJwtGatewayService,
    EnrutadorGatewayService,
    { provide: APP_FILTER, useClass: GatewayProblemFilter },
  ],
  exports: [SeguridadJwtGatewayService, EnrutadorGatewayService],
})
export class GatewayAppModule {}

