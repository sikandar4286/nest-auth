import { Type } from 'class-transformer';
import {
  IsArray,
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';

export class PermissionDto {
  @IsNotEmpty()
  @IsString()
  slug: string;

  @IsOptional()
  @IsString()
  description: string;
}

export class PermissionsDto {
  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PermissionDto)
  permissions: PermissionDto[];
}
