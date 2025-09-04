import {
  Entity,
  ManyToOne,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  JoinColumn,
} from 'typeorm';
import { User } from './user.entity';
import { Permission } from './permission.entity';

@Entity('user_permissions')
export class UserPermission {
  @PrimaryColumn()
  user_id: number;

  @PrimaryColumn()
  permission_id: number;

  @ManyToOne(() => User, (user) => user.userPermissions, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ManyToOne(() => Permission, (perm) => perm.userPermissions, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'permission_id' })
  permission: Permission;

  @Column({ default: true })
  granted: boolean;

  @CreateDateColumn()
  created_at: Date;
}
