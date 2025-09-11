import { HttpException, HttpStatus } from '@nestjs/common';

export class InvalidCredentialException extends HttpException {
  constructor() {
    super('Invalid credentials', HttpStatus.UNAUTHORIZED);
  }
}
