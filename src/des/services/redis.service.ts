import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager';

@Injectable()
export class RedisService {
  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  // Session Management
  async setUserSession(
    userId: number,
    sessionData: any,
    ttl: number = 3600,
  ): Promise<void> {
    const key = `user_session:${userId}`;
    await this.cacheManager.set(key, sessionData, ttl * 1000);
  }

  async getUserSession(userId: number): Promise<any> {
    const key = `user_session:${userId}`;
    return await this.cacheManager.get(key);
  }

  async deleteUserSession(userId: number): Promise<void> {
    const key = `user_session:${userId}`;
    await this.cacheManager.del(key);
  }

  // Permission Caching
  async setUserPermissions(
    userId: number,
    permissions: any,
    ttl: number = 1800,
  ): Promise<void> {
    const key = `user_permissions:${userId}`;
    await this.cacheManager.set(key, permissions, ttl * 1000);
  }

  async getUserPermissions(userId: number): Promise<any> {
    const key = `user_permissions:${userId}`;
    return await this.cacheManager.get(key);
  }

  async deleteUserPermissions(userId: number): Promise<void> {
    const key = `user_permissions:${userId}`;
    await this.cacheManager.del(key);
  }

  // Role Caching
  async setUserRoles(
    userId: number,
    roles: any,
    ttl: number = 1800,
  ): Promise<void> {
    const key = `user_roles:${userId}`;
    await this.cacheManager.set(key, roles, ttl * 1000);
  }

  async getUserRoles(userId: number): Promise<any> {
    const key = `user_roles:${userId}`;
    return await this.cacheManager.get(key);
  }

  async deleteUserRoles(userId: number): Promise<void> {
    const key = `user_roles:${userId}`;
    await this.cacheManager.del(key);
  }

  // Token Management
  async setRefreshToken(
    userId: number,
    token: string,
    ttl: number = 259200,
  ): Promise<void> {
    const key = `refresh_token:${userId}`;
    await this.cacheManager.set(key, token, ttl * 1000);
  }

  async getRefreshToken(userId: number): Promise<string | null> {
    const key = `refresh_token:${userId}`;
    return await this.cacheManager.get(key) || null;
  }

  async deleteRefreshToken(userId: number): Promise<void> {
    const key = `refresh_token:${userId}`;
    await this.cacheManager.del(key);
  }

  // Blacklist tokens (for logout)
  async blacklistToken(token: string, ttl: number = 3600): Promise<void> {
    const key = `blacklist:${token}`;
    await this.cacheManager.set(key, true, ttl * 1000);
  }

  async isTokenBlacklisted(token: string): Promise<boolean> {
    const key = `blacklist:${token}`;
    const result = await this.cacheManager.get(key);
    return !!result;
  }

  // Rate Limiting
  async incrementRateLimit(
    identifier: string,
    ttl: number = 3600,
  ): Promise<number> {
    const key = `rate_limit:${identifier}`;
    const current = (await this.cacheManager.get<number>(key)) || 0;
    const newCount = current + 1;
    await this.cacheManager.set(key, newCount, ttl * 1000);
    return newCount;
  }

  async getRateLimit(identifier: string): Promise<number> {
    const key = `rate_limit:${identifier}`;
    return (await this.cacheManager.get<number>(key)) || 0;
  }

  // Generic cache operations
  async set(key: string, value: any, ttl?: number): Promise<void> {
    await this.cacheManager.set(key, value, ttl ? ttl * 1000 : undefined);
  }

  async get<T>(key: string): Promise<T | null> {
    return await this.cacheManager.get<T>(key) || null;
  }

  async del(key: string): Promise<void> {
    await this.cacheManager.del(key);
  }

  // Clear user-related cache (useful when permissions change)
  async clearUserCache(userId: number): Promise<void> {
    await Promise.all([
      this.deleteUserSession(userId),
      this.deleteUserPermissions(userId),
      this.deleteUserRoles(userId),
      this.deleteRefreshToken(userId),
    ]);
  }

  // Clear all cache with pattern (be careful in production)
  async clearPattern(pattern: string): Promise<void> {
    // This is a simple implementation - in production you might want to use Redis SCAN
    console.warn(
      `Clearing cache pattern: ${pattern} - implement Redis SCAN for production`,
    );
  }
}
