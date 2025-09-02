import { Injectable, Req } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }
  secureRoute(@Req() req): string {
    return `Hello World! ${req.userId}`;
  }
}
