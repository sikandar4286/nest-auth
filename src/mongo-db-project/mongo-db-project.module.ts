import { Module } from '@nestjs/common';
import { MongoDbProjectService } from './mongo-db-project.service';
import { MongoDbProjectController } from './mongo-db-project.controller';

@Module({
  controllers: [MongoDbProjectController],
  providers: [MongoDbProjectService],
})
export class MongoDbProjectModule {}
