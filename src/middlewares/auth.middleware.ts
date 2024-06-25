import { HttpException, Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import { KeycloakService } from '../auth/keycloack.service';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private readonly keycloakService: KeycloakService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7, authHeader.length);

      const decodedToken: any = jwt.decode(token);

      const now = Math.floor(Date.now() / 1000);
      if (!decodedToken) {
        next(
          new HttpException(
            'UnAuthorized Request! Invalid Token, looks like it is malformed',
            401,
          ),
        );
      }
      //token has been expired, refresh the token
      if (decodedToken.exp < now) {
        next(
          new HttpException(
            `refresh Token is not present in the incoming rquest`,
            401,
          ),
        );
      }
      next();
    } else {
      next(
        new HttpException(
          'UnAuthorized Request! Access token is missing in the request',
          401,
        ),
      );
    }
  }
}
