import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
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
      throw new UnauthorizedException('invalid token');
    }

    try {
      const payload = this.jwtService.verify(token);
      request['userId'] = payload.userId;
      console.log(request['userId'], 'request_authentication');
    } catch (error) {
      Logger.error(error);
      throw new UnauthorizedException('invalid token');
    }

    return true;
  }

  private extractTokenFromHeader(request) {
    return request.headers.authorization?.split(' ')[1];
  }
}
