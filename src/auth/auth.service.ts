import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/Login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefrechToken } from './schemas/refresh-tokken.schema';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { ResetToken } from './schemas/reset-tokken.schema';
import { MailService } from 'src/Services/mail.service';
import { RolesService } from 'src/roles/roles.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(RefrechToken.name)
    private readonly refrechTokenModel: Model<RefrechToken>,
    @InjectModel(ResetToken.name)
    private readonly resetTokenModel: Model<ResetToken>,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
    private readonly rolesService: RolesService,
  ) {}

  async signup(signupData: SignupDto) {
    const { name, email, password } = signupData;

    const emailExists = await this.userModel.findOne({ email });

    if (emailExists) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.userModel.create({
      name,
      email,
      password: hashedPassword,
    });

    const { accessToken, refreshToken } = await this.generateToken(
      user._id as string,
    );

    const userObj = user.toObject ? user.toObject() : user;
    const { password: _password, ...userData } = userObj;

    return {
      message: 'Signup successful',
      user: userData,
      accessToken,
      refreshToken,
    };
  }

  async signin(credential: LoginDto) {
    const { email, password } = credential;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { accessToken, refreshToken } = await this.generateToken(
      user._id as string,
    );

    const userObj = user.toObject ? user.toObject() : user;
    const { password: _password, ...userData } = userObj;

    return {
      message: 'Login successful',
      user: userData,
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(refreshToken: string) {
    const storedRefreshToken = await this.refrechTokenModel.findOneAndDelete({
      token: refreshToken,
      expireyDate: { $gt: new Date() },
    });

    if (!storedRefreshToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    return this.generateToken(storedRefreshToken.userId);
  }

  async generateToken(userId: string) {
    const accessToken = this.jwtService.sign(
      { userId: userId },
      { expiresIn: '1h' },
    );

    const refreshToken = uuidv4();

    await this.storeRefreshToken(userId, refreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(userId: string, refreshToken: string) {
    const expireyDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 3);

    const storeToken = await this.refrechTokenModel.updateOne(
      {
        userId,
      },
      {
        $set: {
          token: refreshToken,
          expireyDate,
        },
      },
      {
        upsert: true,
      },
    );

    return storeToken;
  }

  async changePassword(
    oldPassword: string,
    newPassword: string,
    userId: string,
  ) {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    await user.save();

    return {
      message: 'Password changed successfully',
    };
  }

  async forgotPassword(email: string) {
    const user = await this.userModel.findOne({ email });

    if (user) {
      const token = nanoid(64);

      await this.resetTokenModel.create({
        token,
        userId: user._id as string,
        expireyDate: new Date(Date.now() + 1000 * 60 * 60 * 2),
      });

      await this.mailService.sendResetPasswordEmail(email, token);
    }

    return {
      message: 'Password reset email sent',
    };
  }

  async resetPassword(token: string, newPassword: string) {
    const resetToken = await this.resetTokenModel.findOneAndDelete({
      token,
      expireyDate: { $gt: new Date() },
    });

    if (!resetToken) {
      throw new UnauthorizedException('Invalid token');
    }

    const user = await this.userModel.findById(resetToken.userId);

    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return {
      message: 'Password reset successfully',
    };
  }

  async getUserPermissions(userId: string) {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const role = await this.rolesService.getRoleById(user.roleId.toString());
    if (!role) {
      throw new UnauthorizedException('Role not found');
    }

    return role.permissions;
  }
}
