import { DataSource } from 'typeorm';
import { UserSeeder } from './user.seeder';
import { RoleSeeder } from './role.seeder';

export async function DatabaseSeeder(dataSource: DataSource) {
  console.log('🌱 Running all seeders...');

  await RoleSeeder(dataSource);
  await UserSeeder(dataSource);

  console.log('🌱 Seeding finished!');
}
