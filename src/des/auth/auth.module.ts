import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User } from './entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Token } from './entities/token.entity';
import { MailService } from '../services/mail.service';

@Module({
  imports: [TypeOrmModule.forFeature([User, Token])],
  controllers: [AuthController],
  providers: [AuthService, MailService],
})
export class AuthModule {}
