import { DataSource } from 'typeorm';
import { User } from '../auth/entities/user.entity';
import * as bcrypt from 'bcrypt';

export const runSeeder = async (dataSource: DataSource) => {
  const userRepository = dataSource.getRepository(User);

  const existing = await userRepository.findOne({
    where: { email: 'admin@example.com' },
  });
  if (existing) {
    console.log('Admin already exists, skipping seeder.');
    return;
  }

  const admin = userRepository.create({
    username: 'Admin',
    email: 'admin@example.com',
    password_hash: await bcrypt.hash('password123', 10),
    is_active: true,
  });

  await userRepository.save(admin);
  console.log('✅ Admin user seeded successfully!');
};
