import { Body, Controller, Post, Put, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/Login.dto';
import { RefreshTokenDto } from './dtos/RefreshToken.dto';
import { ChangePasswordDto } from './dtos/ChangePassword.dto';
import { AuthenticationGuard } from 'src/guards/authentication.guard';
import { ForgotPasswordDto } from './dtos/ForgotPassword.dto';
import { ResetPasswordDto } from './dtos/ResetPassword.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData);
  }

  @Post('login')
  signin(@Body() credential: LoginDto) {
    return this.authService.signin(credential);
  }

  @Post('refresh-token')
  refreshToken(@Body() refreshToken: RefreshTokenDto) {
    return this.authService.refreshToken(refreshToken.refreshToken);
  }

  @UseGuards(AuthenticationGuard)
  @Put('change-password')
  changePassword(@Body() changePassword: ChangePasswordDto, @Req() req) {
    return this.authService.changePassword(
      changePassword.oldPassword,
      changePassword.newPassword,
      req.userId,
    );
  }

  @Post('forgot-password')
  forgotPassword(@Body() forgotPassword: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPassword.email);
  }

  @Post('reset-password')
  resetPassword(@Body() resetPassword: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPassword.token,
      resetPassword.newPassword,
    );
  }
}
