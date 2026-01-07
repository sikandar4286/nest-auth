import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { RolesModule } from './roles/roles.module';
import configuration from './config/configuration';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DesModule } from './des/des.module';
import { AppRoutingModule } from './app.routing.module';
import { MongoDbProjectModule } from './mongo-db-project/mongo-db-project.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      load: [configuration],
    }),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService) => ({
        secret: configService.get('jwt.secret'),
        // signOptions: { expiresIn: configService.get('jwt.expiresIn') },
      }),
      global: true,
      inject: [ConfigService],
    }),

    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService) => ({
        uri: configService.get('mongodb.uri'),
      }),
      inject: [ConfigService],
    }),

    // TypeOrmModule.forRootAsync({
    //   imports: [ConfigModule],
    //   useFactory: async (configService) => ({
    //     type: 'postgres',
    //     host: configService.get('postgres.host'),
    //     port: configService.get('postgres.port'),
    //     username: configService.get('postgres.username'),
    //     password: configService.get('postgres.password'),
    //     database: configService.get('postgres.database'),
    //     entities: [__dirname + '/**/*.entity{.ts,.js}'],
    //     synchronize: true,
    //     autoLoadEntities: true,
    //   }),
    //   inject: [ConfigService],
    // }),

    AuthModule,
    RolesModule,
    DesModule,
    AppRoutingModule,
    MongoDbProjectModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
