import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { User } from './users/users.entity';
import { Public } from './decorators/public.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Public()
  @Get()
  initApp(): Promise<User> {
    return this.appService.initApp();
  }
}
