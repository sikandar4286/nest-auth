import { Injectable, NotFoundException } from '@nestjs/common';
import { Role } from '../auth/entities/role.entity';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, EntityManager, Repository } from 'typeorm';
import { CreateRoleDto, UpdateRoleDto } from './dto/CreateRoleDto';
import { RolePermission } from '../auth/entities/role-permission.entity';
import { Permission } from '../auth/entities/permission.entity';

@Injectable()
export class RbacService {
  constructor(
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    @InjectRepository(RolePermission)
    private readonly rolePermissionRepository: Repository<RolePermission>,
    @InjectDataSource() private readonly dataSource: DataSource,
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>,
  ) {}

  async getAllRoles() {
    return this.roleRepository.find();
  }

  async getRoleById(id: number) {
    const role = await this.roleRepository.findOne({
      where: { id },
      relations: ['rolePermissions', 'rolePermissions.permission'],
    });

    return {
      role,
    };
  }

  async createRole(createRoleDto: CreateRoleDto) {
    const role = this.roleRepository.create(createRoleDto);
    await this.roleRepository.save(role);

    return {
      message: 'Role created successfully',
      role,
    };
  }

  async updateRole(id: number, updateRoleDto: UpdateRoleDto) {
    const { rolePermissions, ...roleData } = updateRoleDto;

    const role = await this.roleRepository.findOne({ where: { id } });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return await this.dataSource.transaction(async (manager: EntityManager) => {
      await manager.getRepository(Role).update(id, roleData);

      if (Array.isArray(rolePermissions)) {
        const rolePermissionRepo = manager.getRepository(RolePermission);

        await rolePermissionRepo.delete({ role_id: id });

        if (rolePermissions.length > 0) {
          await rolePermissionRepo.save(
            rolePermissions.map((permissionId) => ({
              role_id: id,
              permission_id: permissionId,
            })),
          );
        }
      }

      return {
        message: 'Role updated successfully',
        role: { ...role, ...roleData, rolePermissions },
      };
    });
  }

  async deleteRole(id: number) {
    const role = await this.roleRepository.findOne({ where: { id } });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    const manager = await this.dataSource.transaction(
      async (manager: EntityManager) => {
        await manager.getRepository(RolePermission).delete({ role_id: id });
        await manager.getRepository(Role).delete({ id });

        return {
          message: 'Role deleted successfully',
        };
      },
    );

    return {
      message: 'Role deleted successfully',
    };
  }

  async getAllPermissions() {
    return this.permissionRepository.find();
  }
}
