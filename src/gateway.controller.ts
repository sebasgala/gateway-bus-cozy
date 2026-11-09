import { All, Controller, Req, Res, UseFilters, VERSION_NEUTRAL } from '@nestjs/common';
import { Response } from 'express';
import { PeticionGateway } from './correlacion-y-logs';
import { EnrutadorGatewayService } from './enrutador.service';
import { GatewayProblemFilter } from './problemas';

@Controller({ version: VERSION_NEUTRAL })
@UseFilters(GatewayProblemFilter)
export class GatewayController {
  constructor(private readonly enrutador: EnrutadorGatewayService) {}

  @All()
  async raiz(@Req() req: PeticionGateway, @Res() res: Response): Promise<void> {
    await this.enrutador.reenviarPeticion(req, res);
  }

  @All('*')
  async enrutar(@Req() req: PeticionGateway, @Res() res: Response): Promise<void> {
    await this.enrutador.reenviarPeticion(req, res);
  }
}

