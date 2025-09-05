import { Exclude, Expose } from 'class-transformer';

export class UserResponseDto {
  @Expose()
  id: number;

  @Expose()
  username: string;

  @Expose()
  email: string;

  @Expose({ groups: ['admin'] })
  is_active: boolean;

  @Exclude()
  password_hash: string;

  @Exclude()
  created_at: Date;

  @Exclude()
  updated_at: Date;
}
