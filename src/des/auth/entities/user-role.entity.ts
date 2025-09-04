import {
  Entity,
  ManyToOne,
  PrimaryColumn,
  CreateDateColumn,
  JoinColumn,
} from 'typeorm';
import { Role } from './role.entity';
import { User } from './user.entity';

@Entity('user_roles')
export class UserRole {
  @PrimaryColumn()
  user_id: number;

  @PrimaryColumn()
  role_id: number;

  @ManyToOne(() => User, (user) => user.userRoles, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' }) // 👈 tell TypeORM to use this column
  user: User;

  @ManyToOne(() => Role, (role) => role.userRoles, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'role_id' })
  role: Role;

  @CreateDateColumn()
  granted_at: Date;
}
