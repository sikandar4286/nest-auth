import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { InjectModel } from '@nestjs/mongoose';
import { Request } from 'express';
import { Model } from 'mongoose';
import { Observable } from 'rxjs';
import { AuthService } from 'src/auth/auth.service';
import { User } from 'src/auth/schemas/user.schema';
import { PERMISSIONS_KEY } from 'src/decorators/permissions.decorator';
import { Permission } from 'src/roles/dtos/role.dto';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    // @InjectModel(User.name) private readonly userModel: Model<User>,
    private reflector: Reflector,
    private authService: AuthService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();

    if (!request['userId']) {
      throw new UnauthorizedException('UserId not found');
    }

    const requiredPermissions: Permission[] = this.reflector.getAllAndOverride(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    console.log(requiredPermissions, 'requiredPermissions');

    try {
      const permissions = await this.authService.getUserPermissions(
        request['userId'],
      );

      for (const requiredPermission of requiredPermissions) {
        const userPermission = permissions.find(
          (p) => p.resource === requiredPermission.resource,
        );

        if (!userPermission) {
          throw new ForbiddenException('Forbidden');
        }

        const allActions = requiredPermission.actions.every((a) =>
          userPermission.actions.includes(a),
        );

        if (!allActions) {
          throw new ForbiddenException('Forbidden');
        }
      }
    } catch (error) {
      Logger.error(error);
      throw new ForbiddenException('Forbidden');
    }

    return true;
  }
}
