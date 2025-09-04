import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';

@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: Request = context.switchToHttp().getRequest();

    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('unauthorized');
    }

    try {
      const payload = this.jwtService.verify(token);
      request['userId'] = payload.userId;
    } catch (error) {
      throw new UnauthorizedException('unauthorized');
    }

    return true;
  }

  private extractTokenFromHeader(request) {
    return request.headers.authorization?.split(' ')[1];
  }
}
