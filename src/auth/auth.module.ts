import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/user.schema';
import {
  RefrechToken,
  RefrechTokenSchema,
} from './schemas/refresh-tokken.schema';
import { ResetToken, ResetTokenSchema } from './schemas/reset-tokken.schema';
import { MailService } from 'src/Services/mail.service';
import { RolesModule } from 'src/roles/roles.module';
import { RolesService } from 'src/roles/roles.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: RefrechToken.name, schema: RefrechTokenSchema },
      { name: ResetToken.name, schema: ResetTokenSchema },
    ]),
    RolesModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, MailService],
  exports: [AuthService],
})
export class AuthModule {}
