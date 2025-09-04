import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SigninDto {
  @IsString()
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
