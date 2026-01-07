import { Controller, Get, Inject } from '@nestjs/common';
import { DesService } from './des.service';
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager';

@Controller()
export class DesController {
  constructor(
    private readonly desService: DesService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  @Get()
  desApp() {
    return 'Here is the des app';
  }

  @Get('cache')
  async getCache() {
    const cachedValue = await this.cacheManager.get('DEMO_DATA');
    if (cachedValue) {
      return cachedValue;
    }
    const data = await this.retrieveDataFromDBExample();
    await this.cacheManager.set('DEMO_DATA', data, 30 * 1000);
    return data;
  }

  async retrieveDataFromDBExample() {
    return new Promise((resolve) => {
      setTimeout(() => {
        const demoData = [
          {
            id: 1,
            name: 'John Doe',
            email: 'john.doe@example.com',
          },
          {
            id: 2,
            name: 'Jane Doe',
            email: 'jane.doe@example.com',
          },
          {
            id: 3,
            name: 'Jim Doe',
            email: 'jim.doe@example.com',
          },
        ];
        resolve(demoData);
      }, 1000);
    });
  }
}
