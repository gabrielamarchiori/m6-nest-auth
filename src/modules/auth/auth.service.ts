import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { Injectable } from '@nestjs/common';

interface User {
  userId: string;
  email: string;
  password: string;
}

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  validateUser(email: string, password: string) {
    const user = this.usersService.findByEmail(email);
    if (user && user.password === password) {
      const { userId, email } = user;
      return { userId, email };
    }
    return null;
  }

  async login(user: User) {
    const payload = { email: user.email, sub: user.userId };
    return {
      token: this.jwtService.sign(payload),
    };
  }
}
