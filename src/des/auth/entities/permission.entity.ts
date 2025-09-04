import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { RolePermission } from './role-permission.entity';
import { UserPermission } from './user-permission.entity';

@Entity('permissions')
export class Permission {
  @PrimaryGeneratedColumn('increment')
  id: number;

  @Column({ unique: true })
  slug: string; // e.g., post.create

  @Column({ nullable: true })
  description: string;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;

  @OneToMany(() => RolePermission, (rp) => rp.permission)
  rolePermissions: RolePermission[];

  @OneToMany(() => UserPermission, (up) => up.permission)
  userPermissions: UserPermission[];
}
