import { Module } from '@nestjs/common';
import { DesService } from './des.service';
import { DesController } from './des.controller';
import { AuthModule } from './auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RouterModule } from '@nestjs/core';

const ROUTES = [
  {
    path: 'des',
    module: AuthModule,
  },
];

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
        synchronize: true,
        autoLoadEntities: true,
      }),
      inject: [ConfigService],
    }),

    AuthModule,
    RouterModule.register(ROUTES),
  ],
})
export class DesModule {}
