import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { SigninDto } from './dto/signin.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ChangePasswordDto } from 'src/auth/dtos/ChangePassword.dto';
import { AuthenticationGuard } from '../guards/authentication.guard';
import { ForgotPasswordDto } from './dto/forgotPassword.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() user: SignupDto) {
    return this.authService.signup(user);
  }

  @Post('signin')
  signin(@Body() user: SigninDto) {
    return this.authService.signin(user);
  }

  @Post('refresh-token')
  refreshToken(@Body() refreshToken: RefreshTokenDto) {
    return this.authService.refreshToken(refreshToken.refreshToken);
  }

  @UseGuards(AuthenticationGuard)
  @Post('change-password')
  changePassword(@Body() changePassword: ChangePasswordDto, @Req() req) {
    return this.authService.changePassword(changePassword, req.userId);
  }

  @Post('forgot-password')
  forgotPassword(@Body() forgotPasswordil: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordil.email);
  }

  @Post('reset-password')
  resetPassword(@Body() resetPassword: ResetPasswordDto) {
    return this.authService.resetPassword(resetPassword);
  }
}
