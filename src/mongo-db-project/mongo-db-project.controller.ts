import { Controller, Get } from '@nestjs/common';
import { MongoDbProjectService } from './mongo-db-project.service';

@Controller('mongo-db-project')
export class MongoDbProjectController {
  constructor(private readonly mongoDbProjectService: MongoDbProjectService) {}

  @Get()
  mongoDBApp() {
    return 'Here is the mongo-db-project app';
  }
}
