import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { Role, RoleName } from './entities/role.entity';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';

@Injectable()
export class RolesService {
  constructor(
    @InjectRepository(Role)
    private readonly rolesRepository: Repository<Role>,
  ) {}

  async create(createRoleDto: CreateRoleDto, currentUser: User) {
    if (
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    )
      throw new ForbiddenException('Forbidden Action');
    const role = this.rolesRepository.create(createRoleDto);
    return this.rolesRepository.save(role);
  }

  // --- FIND ALL ---
  async findAll(currentUser: User, page: number = 1, limit: number = 10) {
    if (
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    )
      throw new ForbiddenException('Forbidden Action');

    const skip = (page - 1) * limit;

    const [roles, total] = await this.rolesRepository.findAndCount({
      skip,
      take: limit,
      order: { created_at: 'DESC' },
    });

    return {
      data: roles,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async findOne(id: string, currentUser: User) {
    if (
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    )
      throw new ForbiddenException('Forbidden Action');
    const role = await this.rolesRepository.findOne({
      where: { id },
      // relations: ['users'], // Uncomment if you want to see all users with this role
    });

    if (!role) {
      throw new NotFoundException(`Role with ID ${id} not found`);
    }

    return role;
  }

  async findByName(name: RoleName) {
    const role = await this.rolesRepository.findOne({ where: { name } });

    if (!role) {
      throw new NotFoundException(`Role '${name}' not found`);
    }
    return role;
  }

  async update(id: string, updateRoleDto: UpdateRoleDto, currentUser: User) {
    if (
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    )
      throw new ForbiddenException('Forbidden Action');
    const role = await this.rolesRepository.preload({
      id: id,
      ...updateRoleDto,
    });

    if (!role) {
      throw new NotFoundException(`Role ${id} not found`);
    }

    return this.rolesRepository.save(role);
  }

  async remove(id: string, currentUser: User) {
    if (
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    )
      throw new ForbiddenException('Forbidden Action');
    const result = await this.rolesRepository.delete(id);

    if (result.affected === 0) {
      throw new NotFoundException(`Role ${id} not found`);
    }

    return { message: 'Role deleted successfully' };
  }
}
