import { IsArray, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateRoleDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  slug: string;

  @IsNotEmpty()
  @IsString()
  description: string;
}

export class UpdateRoleDto extends CreateRoleDto {
  @IsOptional()
  @IsArray()
  rolePermissions: number[];
}
