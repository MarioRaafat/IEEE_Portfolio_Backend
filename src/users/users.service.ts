import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { RolesService } from 'src/roles/roles.service';
import { RoleName } from 'src/roles/entities/role.entity';
import * as bcrypt from 'bcrypt';
@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    private readonly rolesService: RolesService,
  ) {}
  async create(createUserDto: CreateUserDto) {
    const { role: roleName, ...userData } = createUserDto;

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(userData.password, salt);

    const roleEntity = await this.rolesService.findByName(roleName);

    if (!roleEntity) {
      throw new NotFoundException(`Role '${roleName}' not found.`);
    }
    const newUser = this.usersRepository.create({
      ...userData,
      password: hashedPassword,
      role_id: roleEntity.id,
    });

    return this.usersRepository.save(newUser);
  }

  async findOne(id: string, currentUser: User) {
    if (
      currentUser.id !== id &&
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    ) {
      throw new ForbiddenException('Forbidden Action');
    }
    const user = await this.usersRepository.findOne({
      where: { id },
      relations: ['role'],
    });

    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  async update(id: string, updateUserDto: UpdateUserDto, currentUser: User) {
    if (
      currentUser.id !== id &&
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    ) {
      throw new ForbiddenException('Forbidden Action');
    }
    const user = await this.usersRepository.preload({
      ...updateUserDto,
      id: id,
    });

    if (!user) {
      throw new NotFoundException(`User ${id} not found`);
    }

    return this.usersRepository.save(user);
  }

  async remove(id: string, currentUser: User) {
    if (
      currentUser.id !== id &&
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    ) {
      throw new ForbiddenException('Forbidden Action');
    }
    const result = await this.usersRepository.delete(id);

    if (result.affected === 0) {
      throw new NotFoundException(`User ${id} not found`);
    }

    return { message: 'User deleted successfully' };
  }

  async validateUserPassword(userId: string, password: string) {
    const user = await this.usersRepository
      .createQueryBuilder('user')
      .addSelect('user.password')
      .where('user.id = :id', { id: userId })
      .getOne();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.password) {
      throw new BadRequestException(
        'User logged in via OAuth2, no password set',
      );
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }
    return user;
  }
}
