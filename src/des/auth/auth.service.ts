import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { MoreThan, Repository } from 'typeorm';
import { SignupDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { nanoid } from 'nanoid';
import { Token, TokenType } from './entities/token.entity';
import { SigninDto } from './dto/signin.dto';
import { ChangePasswordDto } from 'src/auth/dtos/ChangePassword.dto';
import { MailService } from '../services/mail.service';
import { ResetPasswordDto } from './dto/resetPassword.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
  ) {}

  async signup(user: SignupDto) {
    const emailExists = await this.userRepository.findOne({
      where: { email: user.email },
    });

    if (emailExists) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(user.password, 10);

    const newUser = this.userRepository.create({
      ...user,
      password_hash: hashedPassword,
    });

    await this.userRepository.save(newUser);

    const { accessToken, refreshToken } = await this.generateToken(newUser.id);

    const { password_hash, ...userData } = newUser;

    return {
      user: userData,
      accessToken,
      refreshToken,
    };
  }

  async signin(user: SigninDto) {
    const { email, password } = user;
    const userData = await this.userRepository.findOne({ where: { email } });

    if (!userData) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      userData.password_hash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { password_hash, created_at, updated_at, ...rest } = userData;

    const { accessToken, refreshToken } = await this.generateToken(userData.id);

    return {
      user: rest,
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(refreshToken: string) {
    const storedRefreshToken = await this.tokenRepository.findOne({
      where: {
        token: refreshToken,
        type: TokenType.REFRESH,
        expireyDate: MoreThan(new Date()),
      },
    });

    if (!storedRefreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await this.generateToken(storedRefreshToken.userId);

    return {
      accessToken,
      refreshToken: newRefreshToken,
    };
  }

  async changePassword(changePassword: ChangePasswordDto, userId: number) {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(
      changePassword.oldPassword,
      user.password_hash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const hashedPassword = await bcrypt.hash(changePassword.newPassword, 10);

    user.password_hash = hashedPassword;

    await this.userRepository.save(user);

    return {
      message: 'Password changed successfully',
    };
  }

  async forgotPassword(email: string) {
    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    const token = nanoid(64);
    await this.storeToken(user.id, token, TokenType.FORGOT_PASSWORD);

    await this.mailService.sendResetPasswordEmail(user.email, token);

    return {
      message: 'Password reset email sent',
    };
  }

  async resetPassword(resetPassword: ResetPasswordDto) {
    const { token, newPassword } = resetPassword;

    const resetToken = await this.tokenRepository.findOne({
      where: {
        token,
        type: TokenType.FORGOT_PASSWORD,
        expireyDate: MoreThan(new Date()),
      },
    });

    if (!resetToken) {
      throw new UnauthorizedException('Invalid token');
    }

    const user = await this.userRepository.findOne({
      where: { id: resetToken.userId },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }

    user.password_hash = await bcrypt.hash(newPassword, 10);
    await this.userRepository.save(user);

    await this.tokenRepository.delete({
      userId: user.id,
      type: TokenType.FORGOT_PASSWORD,
    });

    return {
      message: 'Password reset successfully',
    };
  }

  async generateToken(userId: number) {
    const accessToken = this.jwtService.sign(
      { userId: userId },
      { expiresIn: '1h' },
    );

    const refreshToken = nanoid(64);
    await this.storeToken(userId, refreshToken, TokenType.REFRESH);

    return { accessToken, refreshToken };
  }

  async storeToken(userId: number, hashToken: string, type: TokenType) {
    const expireyDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 3);

    await this.tokenRepository.upsert(
      {
        userId,
        token: hashToken,
        expireyDate,
        type: type,
      },
      ['userId', 'type'],
    );

    return this.tokenRepository.findOne({
      where: { userId, type: TokenType.REFRESH },
    });
  }
}
