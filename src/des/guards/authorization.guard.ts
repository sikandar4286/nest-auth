import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  PERMISSIONS_KEY,
  ROLES_KEY,
} from '../decorators/role-permission.decorator';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();

    if (!request['userId']) {
      throw new UnauthorizedException('UserId not found');
    }

    const requiredRoles = this.reflector.getAllAndOverride(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const requiredPermissions = this.reflector.getAllAndOverride(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    const user = await this.authService.getUserMe(request['userId']);

    if (user.user.is_admin) return true;

    const roles = user.roles.map((role: { slug: string }) => role.slug);

    const permissions = user.permissions.map(
      (permission: { slug: string }) => permission.slug,
    );

    const userPermissions = user.user_permissions.map(
      (permission: { slug: string }) => permission.slug,
    );

    const allPermissions = new Set([...permissions, ...userPermissions]);

    if (requiredRoles && requiredRoles.length > 0) {
      const hasRoles = requiredRoles.some((role: string) =>
        roles.includes(role),
      );

      if (!hasRoles) {
        throw new ForbiddenException('Forbidden');
      }
    }

    if (requiredPermissions && requiredPermissions.length > 0) {
      const hasPermissions = requiredPermissions.some((permission: string) =>
        allPermissions.has(permission),
      );

      if (!hasPermissions) {
        throw new ForbiddenException('Forbidden');
      }
    }

    return true;
  }
}
