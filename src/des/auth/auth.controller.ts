import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { SigninDto } from './dto/signin.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ChangePasswordDto } from 'src/auth/dtos/ChangePassword.dto';
import { AuthenticationGuard } from '../guards/authentication.guard';
import { ForgotPasswordDto } from './dto/forgotPassword.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { RolesDto, UserRolesDto } from './dto/role.dto';
import { PermissionsDto } from './dto/permission.dto';
import { RolePermissionDto } from './dto/role-permission.dto';
import { Permissions, Roles } from '../decorators/role-permission.decorator';
import { AuthorizationGuard } from '../guards/authorization.guard';

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

  @UseGuards(AuthenticationGuard)
  @Post('create-roles')
  createRoles(@Body() rolesData: RolesDto) {
    return this.authService.createRoles(rolesData);
  }

  @UseGuards(AuthenticationGuard)
  @Post('create-permissions')
  createPermissions(@Body() permissionsData: PermissionsDto) {
    return this.authService.createPermissions(permissionsData);
  }

  @UseGuards(AuthenticationGuard)
  @Post('create-role-permission')
  createRolePermission(@Body() data: RolePermissionDto) {
    return this.authService.createRolePermission(data);
  }

  @UseGuards(AuthenticationGuard)
  @Post('user-roles')
  createUserRoles(@Body() data: UserRolesDto) {
    return this.authService.createUserRoles(data);
  }

  @UseGuards(AuthenticationGuard)
  @Get('users')
  getUsers() {
    return this.authService.getUsers();
  }

  @UseGuards(AuthenticationGuard)
  @Get('user/:id')
  getUser(@Param('id') id: string) {
    return this.authService.getUser(id);
  }

  @Roles(['admin', 'manager'])
  @Permissions(['view-users'])
  @UseGuards(AuthenticationGuard, AuthorizationGuard)
  @Get('user-me')
  getUserMe(@Req() req) {
    return this.authService.getUserMe(req.userId);
  }
}
