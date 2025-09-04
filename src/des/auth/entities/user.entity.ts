import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { UserRole } from './user-role.entity';
import { UserPermission } from './user-permission.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('increment')
  id: number;

  @Column({ unique: false })
  username: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password_hash: string;

  @Column({ default: true })
  is_active: boolean;

  @Column({ type: 'jsonb', nullable: true })
  meta: Record<string, any>;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;

  // Relations
  @OneToMany(() => UserRole, (ur) => ur.user)
  userRoles: UserRole[];

  @OneToMany(() => UserPermission, (up) => up.user)
  userPermissions: UserPermission[];
}
