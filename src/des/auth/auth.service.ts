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
import { UserResponseDto } from './dto/user-response.dto';
import { plainToInstance } from 'class-transformer';
import { Role } from './entities/role.entity';
import { RolesDto, UserRolesDto } from './dto/role.dto';
import { PermissionsDto } from './dto/permission.dto';
import { Permission } from './entities/permission.entity';
import { RolePermissionDto } from './dto/role-permission.dto';
import { RolePermission } from './entities/role-permission.entity';
import { UserRole } from '@/des/auth/entities/user-role.entity';
import { UserPermission } from './entities/user-permission.entity';
import { InvalidCredentialException } from '../exceptions/invalid-credential.exception';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>,
    @InjectRepository(RolePermission)
    private readonly rolePermissionRepository: Repository<RolePermission>,
    @InjectRepository(UserRole)
    private readonly userRoleRepository: Repository<UserRole>,
    @InjectRepository(UserPermission)
    private readonly userPermissionRepository: Repository<UserPermission>,
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
      // throw new UnauthorizedException('Invalid credentials');
      throw new InvalidCredentialException();
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      userData.password_hash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { accessToken, refreshToken } = await this.generateToken(userData.id);

    return {
      user: plainToInstance(UserResponseDto, userData, {
        excludeExtraneousValues: true,
        groups: [userData.is_admin ? 'admin' : 'user'],
      }),
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

  async createRoles(rolesData: RolesDto) {
    const roles = this.roleRepository.create(rolesData.roles);

    await this.roleRepository.save(roles);

    return {
      message: 'Roles created successfully',
      roles,
    };
  }

  async createPermissions(permissionsData: PermissionsDto) {
    const permissions = this.permissionRepository.create(
      permissionsData.permissions,
    );

    await this.permissionRepository.save(permissions);

    return {
      message: 'Permissions created successfully',
      permissions,
    };
  }

  async createRolePermission(data: RolePermissionDto) {
    const permissions = this.rolePermissionRepository.create(data);

    await this.rolePermissionRepository.save(permissions);

    return {
      message: 'Role permission created successfully',
      permissions,
    };
  }

  async createUserRoles(data: UserRolesDto) {
    const userRoles = this.userRoleRepository.create(data.userRoles);

    await this.userRoleRepository.save(userRoles);

    return {
      message: 'User roles created successfully',
      userRoles,
    };
  }

  async getUsers() {
    // const users = await this.userRepository.find({
    //   relations: [
    //     'userRoles',
    //     'userRoles.role',
    //     'userRoles.role.rolePermissions',
    //     'userRoles.role.rolePermissions.permission',
    //     'userPermissions',
    //     'userPermissions.permission',
    //   ],
    // });

    const users = await this.userRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.userRoles', 'userRole')
      .leftJoinAndSelect('userRole.role', 'role')
      .leftJoinAndSelect('role.rolePermissions', 'rolePermission')
      .leftJoinAndSelect('rolePermission.permission', 'permission')
      .leftJoinAndSelect('user.userPermissions', 'userPermission')
      .leftJoinAndSelect('userPermission.permission', 'directPermission')
      .getMany();

    return {
      users,
    };
  }

  async getUser(id: string) {
    const user = await this.userRepository.findOne({
      where: { id: Number(id) },
      relations: [
        'userRoles',
        'userRoles.role',
        'userRoles.role.rolePermissions',
        'userRoles.role.rolePermissions.permission',
        'userPermissions',
        'userPermissions.permission',
      ],
    });

    return {
      user,
    };
  }

  async getUserMe(id: string) {
    const userId = Number(id);

    if (!userId) {
      throw new BadRequestException('Invalid user ID');
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: [
        'id',
        'username',
        'email',
        'is_admin',
        'is_active',
        'meta',
        'created_at',
        'updated_at',
      ],
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.is_admin) {
      return {
        user: { ...user, is_admin: true },
        roles: [],
        permissions: [],
        user_permissions: [],
      };
    }

    // Step 1: Get user roles only (no permissions to avoid join explosion)
    const userRoles = await this.userRoleRepository
      .createQueryBuilder('ur')
      .leftJoinAndSelect('ur.role', 'role')
      .where('ur.user_id = :userId', { userId })
      .getMany();

    // Step 2: Check for admin role
    const isAdminRole = userRoles.some(
      (ur) =>
        ur.role?.slug?.toLowerCase() === 'admin' ||
        ur.role?.name?.toLowerCase() === 'admin',
    );

    if (isAdminRole) {
      return {
        user: { ...user, is_admin: true },
        roles: [],
        permissions: [],
        user_permissions: [],
      };
    }

    // Step 3: Get role permissions separately (avoiding join explosion)
    const roleIds = userRoles.map((ur) => ur.role.id);
    const rolePermissions =
      roleIds.length > 0
        ? await this.rolePermissionRepository
            .createQueryBuilder('rp')
            .leftJoinAndSelect('rp.permission', 'permission')
            .where('rp.role_id IN (:...roleIds)', { roleIds })
            .getMany()
        : [];

    // Step 4: Get user permissions
    const userPerms = await this.userPermissionRepository
      .createQueryBuilder('up')
      .leftJoinAndSelect('up.permission', 'permission')
      .where('up.user_id = :userId', { userId })
      .andWhere('up.granted = :granted', { granted: true })
      .getMany();

    const userPermissions = userPerms.map((up) => ({
      id: up.permission.id,
      slug: up.permission.slug,
      description: up.permission.description,
      granted: up.granted,
      created_at: up.created_at,
    }));

    // Step 5: Build role-permission mapping
    const rolePermissionMap = new Map<
      number,
      Array<{ id: number; slug: string; description: string }>
    >();

    rolePermissions.forEach((rp) => {
      if (!rolePermissionMap.has(rp.role_id)) {
        rolePermissionMap.set(rp.role_id, []);
      }
      rolePermissionMap.get(rp.role_id)!.push({
        id: rp.permission.id,
        slug: rp.permission.slug,
        description: rp.permission.description,
      });
    });

    // Step 6: Format response
    const roles = userRoles.map((ur) => ({
      id: ur.role.id,
      slug: ur.role.slug,
      name: ur.role.name,
      description: ur.role.description,
      granted_at: ur.granted_at,
      permissions: rolePermissionMap.get(ur.role.id) || [],
    }));

    const permissions = rolePermissions.map((rp) => ({
      id: rp.permission.id,
      slug: rp.permission.slug,
      description: rp.permission.description,
    }));

    return {
      user: { ...user, is_admin: isAdminRole },
      roles,
      permissions,
      user_permissions: userPermissions,
    };
  }
}
