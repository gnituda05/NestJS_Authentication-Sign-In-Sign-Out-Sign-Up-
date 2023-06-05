import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import {JwtModule} from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UsersModule } from 'src/users/users.module';
import { UsersService } from 'src/users/users.service';
import { PrismaService } from 'prisma/prisma.service';


@Module({
  imports:[JwtModule, PassportModule],
  controllers: [AuthController],
  providers: [AuthService, UsersModule, UsersService, PrismaService]
})
export class AuthModule {}
