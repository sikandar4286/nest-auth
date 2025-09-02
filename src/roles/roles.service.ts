import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Role } from './Schemas/role.schema';
import { Model } from 'mongoose';
import { CreateRoleDto } from './dtos/role.dto';

@Injectable()
export class RolesService {
  constructor(
    @InjectModel(Role.name) private readonly roleModel: Model<Role>,
  ) {}

  async createRole(createRoleDto: CreateRoleDto) {
    const role = await this.roleModel.create(createRoleDto);
    return role;
  }

  async getAllRoles() {
    const roles = await this.roleModel.find();
    return roles;
  }

  async getRoleById(roleId: string) {
    const role = await this.roleModel.findById(roleId);
    return role;
  }
}
