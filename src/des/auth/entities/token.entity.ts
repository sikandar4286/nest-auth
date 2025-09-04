import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';

export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
  RESET = 'reset',
  FORGOT_PASSWORD = 'forgot_password',
}

@Entity('tokens')
@Unique(['userId', 'type'])
export class Token {
  @PrimaryGeneratedColumn('increment')
  id: number;

  @Column({ nullable: false })
  token: string;

  @Column({ nullable: false })
  userId: number;

  @Column({ type: 'enum', enum: TokenType, nullable: false })
  type: TokenType;

  @Column({ unique: false, nullable: false })
  expireyDate: Date;

  @CreateDateColumn({ nullable: false })
  created_at: Date;
}
