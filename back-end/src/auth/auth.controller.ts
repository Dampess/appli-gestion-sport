import {
  Controller,
  Body,
  Post,
  Get,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { LocalAuthGuard } from './local-auth.guard';
import { Public } from 'src/decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private usersService: UsersService,
  ) {}

  @Public()
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async signIn(
    @Body('email') email: string,
    @Body('password') password: string,
  ) {
    console.log('SignIn');

    return this.authService.signIn(email, password);
  }

  @Get('profile')
  getProfile(@Request() req) {
    // Récupérer les informations de l'utilisateur à partir du token JWT
    return req.user;
  }

  @Public()
  @Post('resetpassword')
  async requestPasswordReset(@Body('email') email: string) {
    return this.usersService.requestPasswordReset(email);
  }
}
