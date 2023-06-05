import { BadRequestException, ForbiddenException, Injectable, HttpException, HttpStatus, Body, HttpCode, Post } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret} from '../utils/constants';
import { Request, Response } from 'express';
import { SignUpDto } from './dto/signup.dto';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService) {}

    async signup(dto: SignUpDto) {
        const {firstName, lastName, middleInitial, email, password, roleId,statusId, departmentId} = dto;
        const foundUser = await this.prisma.users.findUnique({where: {email}})

        if(foundUser){
            throw new BadRequestException('Email already exists')
        }
        const hashedPassword = await this.hashPassword(password)

        await this.prisma.users.create({
          
          data: {
    // @ts-ignore
    firstName, lastName, middleInitial, email, hashedPassword, roleId,statusId, departmentId 
            }
        })
        return{message: 'User created sucessfull!'};
    }


    async signin(dto: AuthDto, req: Request, res: Response) {
        const { email, password } = dto;
      
        const foundUser = await this.prisma.users.findUnique({ where: { email: email } });
      
        if (!foundUser) {
          throw new HttpException('LOGIN.USER_NOT_FOUND', HttpStatus.NOT_FOUND);
        }
      
        const isMatch = await this.comparePasswords({ password, hash: foundUser.hashedPassword });
        if (!isMatch) {
          throw new BadRequestException('Wrong credentials password!');
        }
      
        const token = await this.signToken({ id: foundUser.id, email: foundUser.email });
        if (!token) {
          throw new ForbiddenException('Could not Signin');
        }
      
        res.cookie('token', token, {});
        return res.send({ message: 'Logged in successfully', token });
      }
      

    async signout(req: Request, res: Response) {
        res.clearCookie('token');
        return res.send({ message: 'Logged out succesfully!'});
    }

    async hashPassword(password: string) {
      const salt = await bcrypt.genSalt();
        return await bcrypt.hash(password,salt);
    }

    async comparePasswords(args: {password: string, hash:string}){
        return await bcrypt.compare(args.password, args.hash);
    }
    
    async signToken(args: { id: string, email: string }) {
        const secret = jwtSecret;
        const options = { expiresIn: '1h' };
      
        const payload = {
          id: args.id,
          email: args.email,
        };
      
        const token = jwt.sign(payload, secret, options);
      
        const updatedUser = await this.prisma.users.update({
          where: { id: args.id },
          data: { token: token },
        });
      
        if (!updatedUser) {
          throw new HttpException('Could not update user', HttpStatus.INTERNAL_SERVER_ERROR);
        }
      
        return token;
      }
    
}



