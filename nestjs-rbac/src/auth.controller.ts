import { Body, Controller, Post } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

type LoginBody = { email?: string; password?: string };

const accounts = [
  { id: 1, email: 'user@example.com', password: 'user-password', role: 'user' },
  { id: 2, email: 'admin@example.com', password: 'admin-password', role: 'admin' },
];

@Controller('auth')
export class AuthController {
  constructor(private readonly jwtService: JwtService) {}

  @Post('login')
  login(@Body() body: LoginBody) {
    const account = accounts.find(
      (candidate) =>
        candidate.email === body.email && candidate.password === body.password,
    );

    if (!account) {
      return { error: 'Invalid email or password' };
    }

    const { password: _password, ...user } = account;
    return { accessToken: this.jwtService.sign(user), user };
  }
}
