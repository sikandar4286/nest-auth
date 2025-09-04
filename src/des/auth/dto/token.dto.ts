import {
  IsDate,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsString,
} from 'class-validator';
import { TokenType } from '../entities/token.entity';

export class TokenDto {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsNumber()
  @IsNotEmpty()
  userId: number;

  @IsEnum(TokenType)
  @IsNotEmpty()
  type: TokenType;

  @IsDate()
  expireyDate: Date;
}
