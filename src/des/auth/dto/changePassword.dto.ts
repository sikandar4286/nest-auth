import { IsNotEmpty, IsString } from 'class-validator';

class ChangePasswordDto {
  @IsNotEmpty()
  @IsString()
  oldPassword: string;

  @IsNotEmpty()
  @IsString()
  newPassword: string;
}
