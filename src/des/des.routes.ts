import { AuthModule } from './auth/auth.module';
import { DesModule } from './des.module';

export const DES_ROUTES = [
  {
    path: 'des',
    module: DesModule,
    children: [
      {
        path: '',
        module: AuthModule,
      },
    ],
  },
];
