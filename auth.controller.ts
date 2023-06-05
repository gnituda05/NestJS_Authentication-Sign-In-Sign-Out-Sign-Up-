import { Body, Controller, HttpStatus, HttpCode, Get, Patch, Post ,Request, Response, UseGuards, ValidationPipe, NotFoundException, Redirect, Query, BadRequestException} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { UsersService } from 'src/users/users.service';

import * as bcrypt from 'bcrypt';
import { SignUpDto } from './dto/signup.dto';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService, 
    private prisma: PrismaService, private readonly userService: UsersService) {}

  @Post('signup')
  signup(@Body() dto: SignUpDto) { 
    return this.authService.signup(dto);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  signin(@Body() dto: AuthDto, @Request() req, @Response() res) {
  return this.authService.signin(dto, req, res);
}

  @Get('signout')
  signout(@Request() req, @Response() res) {
    return this.authService.signout(req, res);
  }  

  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
    await this.userService.sendPasswordResetEmail(email);
    return { message: 'Password reset email sent' };
  }


  @Post('reset-password')
  async resetPassword(@Body()  { email, resetToken, newpassword }: { email: string; resetToken: string; newpassword: string }) 
  {
    
    const user = await this.prisma.users.findUnique({ where: { email } });
    if (!user) {
      throw new Error('User not found');
    }
    if (user.resetToken !== resetToken) {
      throw new Error('Invalid reset token');
    }
    const hashedPassword = await this.hashPassword(newpassword)

    await this.prisma.users.update({
      where: { email },
      data: { hashedPassword: hashedPassword, resetToken: undefined },
    });

    return { message: 'Password reset successful' };
  }

  async hashPassword(password: string) {
    const salt = await bcrypt.genSalt();
    return await bcrypt.hash(password,salt);
}
}


   
