// src/database/seeders/role.seeder.ts
import { DataSource } from 'typeorm';
import { Role } from '../../auth/entities/role.entity';

export async function RoleSeeder(dataSource: DataSource) {
  const roleRepository = dataSource.getRepository(Role);

  const count = await roleRepository.count();
  if (count > 0) return console.log('⚠️ Roles already seeded, skipping.');

  const roles = roleRepository.create([{ name: 'Admin' }, { name: 'User' }]);

  await roleRepository.save(roles);
  console.log('✅ Roles seeded!');
}
