import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User } from './entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Token } from './entities/token.entity';
import { MailService } from '../services/mail.service';
import { Role } from './entities/role.entity';
import { Permission } from './entities/permission.entity';
import { RolePermission } from './entities/role-permission.entity';
import { UserRole } from './entities/user-role.entity';
import { UserPermission } from './entities/user-permission.entity';
import { RedisService } from '../services/redis.service';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import KeyvRedis from '@keyv/redis';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      Token,
      Role,
      Permission,
      RolePermission,
      UserRole,
      UserPermission,
    ]),
    CacheModule.registerAsync({
      useFactory: async (configService) => {
        return {
          ttl: 30 * 1000,
          stores: [
            new KeyvRedis('redis://localhost:6379', {
              namespace: 'my-redis-namespace',
            }),
          ],
        };
      },
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, MailService, RedisService],
  exports: [AuthService, RedisService],
})
export class AuthModule {}
