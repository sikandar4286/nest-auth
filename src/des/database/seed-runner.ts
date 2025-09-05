import dataSource from '../data-source';
import { DatabaseSeeder } from './seeders';

(async () => {
  try {
    const ds = await dataSource.initialize();
    await DatabaseSeeder(ds);
    await ds.destroy();
    process.exit(0);
  } catch (err) {
    console.error('❌ Error running seeders:', err);
    process.exit(1);
  }
})();
