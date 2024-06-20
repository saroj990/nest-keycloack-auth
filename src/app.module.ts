import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { KeycloakService } from './auth/keycloack.service';
import { TokenRefreshMiddleware } from './middlewares/token-refresh.middleware';
import { AuthController } from './auth/auth.controller';

@Module({
  imports: [],
  controllers: [AppController, AuthController],
  providers: [AppService, KeycloakService],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(TokenRefreshMiddleware)
      .exclude({ path: 'auth/login', method: RequestMethod.POST })
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
