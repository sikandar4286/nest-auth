import { Module } from '@nestjs/common';
import { RouterModule } from '@nestjs/core';
import { DES_ROUTES } from './des/des.routes';

const ROUTES = [...DES_ROUTES];

@Module({
  imports: [RouterModule.register(ROUTES)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
