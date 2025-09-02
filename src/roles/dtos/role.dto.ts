import { Type } from 'class-transformer';
import {
  ArrayUnique,
  IsArray,
  IsEnum,
  IsNotEmpty,
  IsString,
  ValidateNested,
} from 'class-validator';
import { Action } from '../enums/action.enum';

export class CreateRoleDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Permission)
  permissions: Permission[];
}

export class Permission {
  @IsNotEmpty()
  @IsString()
  resource: string;

  @IsNotEmpty()
  @ArrayUnique()
  @IsEnum(Action, { each: true })
  actions: Action[];
}
