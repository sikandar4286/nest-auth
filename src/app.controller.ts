import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthenticationGuard } from './guards/authentication.guard';
import { Permissions } from './decorators/permissions.decorator';
import { Action } from './roles/enums/action.enum';
import { Resource } from './roles/enums/resource.enum';
import { AuthorizationGuard } from './guards/authorization.guard';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('secure-route')
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Permissions([{ resource: Resource.SecureRoute, actions: [Action.Read] }])
  secureRoute(@Req() req): string {
    return this.appService.secureRoute(req);
  }
}
