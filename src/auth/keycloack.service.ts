import { Injectable, HttpException } from '@nestjs/common';
import axios from 'axios';
import * as dotenv from 'dotenv';

dotenv.config();

@Injectable()
export class KeycloakService {
  private readonly keycloakUrl: string = process.env.KEYCLOAK_URL;
  private readonly realm: string = process.env.KEYCLOAK_REALM;
  private readonly clientId: string = process.env.KEYCLOAK_CLIENT_ID;
  private readonly clientSecret: string = process.env.KEYCLOAK_CLIENT_SECRET;
  private readonly adminUsername: string = process.env.KEYCLOAK_ADMIN_USERNAME;
  private readonly adminPassword: string = process.env.KEYCLOAK_ADMIN_PASSWORD;

  private accessToken: string;
  private refreshToken: string;

  async authenticate(username: string, password: string): Promise<any> {
    const url = `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`;

    const params = new URLSearchParams();
    params.append('client_id', this.clientId);
    params.append('client_secret', this.clientSecret);
    params.append('grant_type', 'password');
    params.append('username', username);
    params.append('password', password);

    try {
      const response = await axios.post(url, params);
      this.accessToken = response.data.access_token;
      this.refreshToken = response.data.refresh_token;
      return response.data;
    } catch (error) {
      throw new HttpException(
        `Failed to authenticate: ${(error as Error).message}`,
        401,
      );
    }
  }

  async refreshAccessToken(refreshToken: string): Promise<any> {
    const url = `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`;

    const params = new URLSearchParams();
    params.append('client_id', this.clientId);
    params.append('client_secret', this.clientSecret);
    params.append('grant_type', 'refresh_token');
    params.append('refresh_token', refreshToken);

    try {
      const response = await axios.post(url, params);
      this.accessToken = response.data.access_token;
      this.refreshToken = refreshToken;
      return response.data;
    } catch (error) {
      console.log('Error: ', error);
      throw new HttpException(
        `Failed to refresh token: ${(error as Error).message}`,
        401,
      );
    }
  }

  getAccessToken(): string {
    return this.accessToken;
  }

  getRefreshToken(): string {
    return this.refreshToken;
  }

  async getAdminAccessToken(): Promise<string> {
    const url = `${this.keycloakUrl}/realms/${this.realm}/protocol/openid-connect/token`;

    const params = new URLSearchParams();
    params.append('client_id', this.clientId);
    params.append('client_secret', this.clientSecret);
    params.append('grant_type', 'password');
    params.append('username', this.adminUsername);
    params.append('password', this.adminPassword);

    try {
      const response = await axios.post(url, params);
      return response.data.access_token;
    } catch (error) {
      throw new HttpException(
        `Failed to get admin access token: ${(error as Error).message}`,
        401,
      );
    }
  }

  async changePassword(
    username: string,
    oldPassword: string,
    newPassword: string,
  ): Promise<void> {
    // Authenticate user to ensure old password is correct
    await this.authenticate(username, oldPassword);

    const adminToken = await this.getAdminAccessToken();
    const userId = await this.getUserId(username, adminToken);

    const url = `${this.keycloakUrl}/admin/realms/${this.realm}/users/${userId}/reset-password`;

    const config = {
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
    };

    const data = {
      type: 'password',
      value: newPassword,
      temporary: false,
    };

    try {
      await axios.put(url, data, config);
    } catch (error) {
      throw new HttpException(
        `Failed to change password:${(error as Error).message}`,
        400,
      );
    }
  }

  private async getUserId(username: string, token: string): Promise<string> {
    const url = `${this.keycloakUrl}/admin/realms/${this.realm}/users?username=${username}`;

    const config = {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    };

    try {
      const response = await axios.get(url, config);
      if (response.data.length === 0) {
        throw new Error('User not found');
      }
      return response.data[0].id;
    } catch (error) {
      throw new HttpException(
        `Failed to get user ID: ${(error as Error).message}`,
        400,
      );
    }
  }
}
