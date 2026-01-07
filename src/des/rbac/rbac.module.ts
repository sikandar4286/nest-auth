import { Module } from '@nestjs/common';
import { RbacService } from './rbac.service';
import { RbacController } from './rbac.controller';
import { Role } from '../auth/entities/role.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RolePermission } from '../auth/entities/role-permission.entity';
import { Permission } from '../auth/entities/permission.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Role, RolePermission, Permission])],
  controllers: [RbacController],
  providers: [RbacService],
})
export class RbacModule {}
