import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  private readonly users = [
    {
      userId: 1,
      email: 'felipe@kenzie.com',
      password: 'kenzie',
    },
    {
      userId: 2,
      email: 'alex@kenzie.com',
      password: 'kenzie',
    },
  ];

  findByEmail(email: string) {
    const user = this.users.find((user) => user.email === email);
    return user;
  }

  findAll() {
    return this.users;
  }
}
