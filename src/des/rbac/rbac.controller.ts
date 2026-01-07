import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
} from '@nestjs/common';
import { RbacService } from './rbac.service';
import { CreateRoleDto, UpdateRoleDto } from './dto/CreateRoleDto';

@Controller('rbac')
export class RbacController {
  constructor(private readonly rbacService: RbacService) {}

  @Get('roles')
  getRoles() {
    return this.rbacService.getAllRoles();
  }

  @Get('roles/:id')
  getRoleById(@Param('id') id: string) {
    return this.rbacService.getRoleById(Number(id));
  }

  @Post('roles')
  createRole(@Body() createRoleDto: CreateRoleDto) {
    return this.rbacService.createRole(createRoleDto);
  }

  @Put('roles/:id')
  updateRole(@Param('id') id: string, @Body() updateRoleDto: UpdateRoleDto) {
    return this.rbacService.updateRole(Number(id), updateRoleDto);
  }

  @Delete('roles/:id')
  deleteRole(@Param('id') id: string) {
    return this.rbacService.deleteRole(Number(id));
  }

  @Get('permissions')
  getPermissions() {
    return this.rbacService.getAllPermissions();
  }
}
