import { Module } from '@nestjs/common';
import { DesService } from './des.service';
import { DesController } from './des.controller';
import { AuthModule } from './auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RbacModule } from './rbac/rbac.module';
import { CacheModule } from '@nestjs/cache-manager';
import KeyvRedis from '@keyv/redis';

@Module({
  controllers: [DesController],
  providers: [DesService],
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService) => ({
        type: 'postgres',
        host: configService.get('postgres.host'),
        port: configService.get('postgres.port'),
        username: configService.get('postgres.username'),
        password: configService.get('postgres.password'),
        database: configService.get('postgres.database'),
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        synchronize: false,
        autoLoadEntities: true,

        // synchronize: process.env.NODE_ENV !== 'production',
        // migrationsRun: true,
        migrationsRun: process.env.NODE_ENV === 'production',
        migrations: [__dirname + '../des/migrations/**/*{.ts,.js}'],
      }),
      inject: [ConfigService],
    }),

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

    AuthModule,
    RbacModule,
  ],
})
export class DesModule {}
