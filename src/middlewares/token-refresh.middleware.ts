import { HttpException, Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import { KeycloakService } from '../auth/keycloack.service';

@Injectable()
export class TokenRefreshMiddleware implements NestMiddleware {
  constructor(private readonly keycloakService: KeycloakService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    console.log('inside middleware fetching access_token');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7, authHeader.length);

      const decodedToken: any = jwt.decode(token);
      console.log('decoded token: ', decodedToken);

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
        console.log('token has expired, now checking refreshtoken');
        const refreshToken = req.body.refresh_token;

        if (!refreshToken) {
          next(
            new HttpException(
              `refresh Token is not present in the incoming rquest`,
              401,
            ),
          );
        }

        console.log('refresh token found: ', refreshToken);
        try {
          const newTokens =
            await this.keycloakService.refreshAccessToken(refreshToken);
          console.log(
            'token has been refreshed, new access token :',
            newTokens.access_token,
          );
          // Update the authorization header with the new token
          // req.headers.authorization = `Bearer ${newTokens.access_token}`;
        } catch (error) {
          return res.status(401).json({ message: 'Failed to refresh token' });
        }
      }
      console.log('token is fresh');
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
