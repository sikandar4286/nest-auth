import { Controller, Get } from '@nestjs/common';
import { DesService } from './des.service';

@Controller()
export class DesController {
  constructor(private readonly desService: DesService) {}

  @Get()
  desApp() {
    return 'Here is the des app';
  }
}
