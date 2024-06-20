import {
  Controller,
  Post,
  Body,
  BadRequestException,
  Get,
} from '@nestjs/common';
import { KeycloakService } from './keycloack.service';
import { loginSchema } from './auth.validation';

@Controller('auth')
export class AuthController {
  constructor(private readonly keycloakService: KeycloakService) {}

  @Post('login')
  async login(@Body() body: { username: string; password: string }) {
    const { error, value } = loginSchema.validate(body);
    if (error) {
      throw new BadRequestException('Validation failed', error.message);
    }
    const { username, password } = value;
    return this.keycloakService.authenticate(username, password);
  }

  @Post('change-password')
  async changePassword(
    @Body() body: { username: string; password: string; newPassword: string },
  ) {
    const { username, password, newPassword } = body;
    return this.keycloakService.changePassword(username, password, newPassword);
  }

  @Get('/ping')
  async ping() {
    return {
      message: 'authenticated route',
    };
  }
}
