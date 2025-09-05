Setup in NestJS

1. Turn off synchronize in production

synchronize: process.env.NODE_ENV !== 'production',
migrationsRun: process.env.NODE_ENV === 'production', // auto-run migrations on startup
migrations: [__dirname + '/migrations/**/*{.ts,.js}'],

2. Install CLI

npm install -D ts-node typeorm

3. Create a data-source.ts file

This is required for TypeORM CLI:

import { DataSource } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { config } from 'dotenv';
import { join } from 'path';

config(); // load .env

export default new DataSource({
type: 'postgres',
host: process.env.POSTGRES_HOST,
port: Number(process.env.POSTGRES_PORT),
username: process.env.POSTGRES_USERNAME,
password: process.env.POSTGRES_PASSWORD,
database: process.env.POSTGRES_DATABASE,
entities: [join(__dirname, '**/*.entity{.ts,.js}')],
migrations: [join(__dirname, 'migrations/*{.ts,.js}')],
});

adjust path according

4. Generate a migration

npx typeorm-ts-node-commonjs migration:generate -d src/des/data-source.ts src/des/migrations/InitSchema

This creates a file like:

export class InitSchema1678901234567 {
async up(queryRunner: QueryRunner): Promise<void> {
await queryRunner.query(`CREATE TABLE "users" (...)`);
}

async down(queryRunner: QueryRunner): Promise<void> {
await queryRunner.query(`DROP TABLE "users"`);
}
}

5. Run migrations

Apply them to DB:

npx typeorm-ts-node-commonjs migration:run -d src/data-source.ts

Revert last migration:

npx typeorm-ts-node-commonjs migration:revert -d src/des/data-source.ts

side note: Create an empty migration and write SQL manually

If you want full control:

npx typeorm-ts-node-commonjs migration:create src/migrations/InitSchema

import { MigrationInterface, QueryRunner } from "typeorm";

export class InitSchema1725470000000 implements MigrationInterface {
public async up(queryRunner: QueryRunner): Promise<void> {
// write your schema here (or use queryRunner.createTable, etc.)
}

public async down(queryRunner: QueryRunner): Promise<void> {
// reverse changes here
}
}

Then you run:

npx typeorm-ts-node-commonjs migration:run -d src/des/data-source.ts
