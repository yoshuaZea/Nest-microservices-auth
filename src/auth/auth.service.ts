import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('Mongo DB connected!');
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    try {
      const { email, name, password } = registerUserDto;

      const userExists = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (userExists) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: `User already exists`,
        });
      }

      const user = await this.user.create({
        data: {
          email,
          name,
          password: bcrypt.hashSync(password, 12), // * Hash password
        },
      });

      // * Remove password
      // delete user.password;

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _password, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    try {
      const { email, password } = loginUserDto;

      const user = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (!user) {
        throw new RpcException({
          status: HttpStatus.NOT_FOUND,
          message: `User ${email} not found`,
        });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: `Password incorrect`,
        });
      }

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _password, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid token',
      });
    }
  }
}
