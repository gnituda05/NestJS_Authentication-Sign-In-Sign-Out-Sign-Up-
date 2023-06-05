import { IsNotEmpty, IsString, IsEmail, Length, IsNumber } from 'class-validator';

export class SignUpDto {
  


  @IsString()
  @IsNotEmpty()
  public firstName: string;
  
  @IsString()
  @IsNotEmpty()
  public lastName: string;

  @IsString()
  public middleInitial: string;

  @IsEmail()
  @IsNotEmpty()
  public email: string;

  @IsNotEmpty()
  @IsString()
  @Length(3, 20, { message: 'Password has to be at between 3 and 20 chars' })
  public password: string;

  @IsNumber()
  public roleId: number;

  @IsNumber()
  public statusId: number;

  @IsNumber()
  public departmentId: number;

}