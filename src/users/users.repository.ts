import {
  Injectable,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { ERROR_MESSAGES } from 'src/constants/swagger-messages';

@Injectable()
export class UsersRepository {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async findById(id: string, relations: string[] = ['role']): Promise<User> {
    try {
      const user = await this.userRepository.findOne({
        where: { id },
        relations,
      });

      if (!user) {
        throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
      }

      return user;
    } catch (error) {
      console.error('Error in findById:', error);
      throw new InternalServerErrorException(
        ERROR_MESSAGES.FAILED_TO_FETCH_FROM_DB,
      );
    }
  }

  async findByEmail(
    email: string,
    relations: string[] = ['role'],
  ): Promise<User | null> {
    try {
      return await this.userRepository.findOne({
        where: { email },
        relations,
      });
    } catch (error) {
      console.error('Error in findByEmail:', error);
      throw new InternalServerErrorException(
        ERROR_MESSAGES.FAILED_TO_FETCH_FROM_DB,
      );
    }
  }

  async findByUsername(
    username: string,
    relations: string[] = ['role'],
  ): Promise<User | null> {
    try {
      return await this.userRepository.findOne({
        where: { username },
        relations,
      });
    } catch (error) {
      console.error('Error in findByUsername:', error);
      throw new InternalServerErrorException(
        ERROR_MESSAGES.FAILED_TO_FETCH_FROM_DB,
      );
    }
  }

  async findByIdWithPassword(
    id: string,
    relations: string[] = ['role'],
  ): Promise<User> {
    try {
      const user = await this.userRepository
        .createQueryBuilder('user')
        .leftJoinAndSelect('user.role', 'role')
        .where('user.id = :id', { id })
        .addSelect('user.password')
        .getOne();

      if (!user) {
        throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
      }

      return user;
    } catch (error) {
      console.error('Error in findByIdWithPassword:', error);
      throw new InternalServerErrorException(
        ERROR_MESSAGES.FAILED_TO_FETCH_FROM_DB,
      );
    }
  }

  async create(userData: Partial<User>): Promise<User> {
    try {
      const user = this.userRepository.create(userData);
      const savedUser = await this.userRepository.save(user);
      return await this.findById(savedUser.id);
    } catch (error) {
      throw new InternalServerErrorException(
        ERROR_MESSAGES.FAILED_TO_SAVE_IN_DB,
      );
    }
  }

  /**
   * Update user with provided fields only
   * @returns Updated user entity
   */
  async update(id: string, updateData: Partial<User>): Promise<User> {
    try {
      await this.userRepository.update(id, updateData);
      return await this.findById(id);
    } catch (error) {
      console.error('Error in update:', error);
      throw new InternalServerErrorException(
        ERROR_MESSAGES.FAILED_TO_UPDATE_IN_DB,
      );
    }
  }

  async delete(id: string): Promise<{ success: boolean; message: string }> {
    try {
      const result = await this.userRepository.delete(id);

      if (result.affected === 0) {
        throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
      }

      return {
        success: true,
        message: 'User deleted successfully',
      };
    } catch (error) {
      console.error('Error in delete:', error);
      throw new InternalServerErrorException(
        ERROR_MESSAGES.FAILED_TO_DELETE_FROM_DB,
      );
    }
  }
}
