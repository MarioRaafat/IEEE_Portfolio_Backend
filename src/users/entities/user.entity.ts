import { Exclude } from 'class-transformer';
import { Role } from '../../roles/entities/role.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true, select: false })
  @Exclude()
  password: string;

  @Column('uuid')
  role_id: string;

  @ManyToOne(() => Role, (role) => role.users, {
    nullable: false,
    onUpdate: 'CASCADE',
    onDelete: 'RESTRICT',
  })
  @JoinColumn({ name: 'role_id' })
  role: Role;

  @Column({ nullable: true })
  avatar_url: string;

  @Column({ type: 'text', nullable: true })
  bio: string;

  @Column({ nullable: true })
  phone: string;

  @Column()
  faculty: string;

  @Column()
  university: string;

  @Column({ type: 'int', width: 1 })
  academic_year: number;

  @Column({ default: 'General' })
  major: string;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;

  @Column({ default: false })
  verified_email: boolean;

  @Column({ default: true })
  is_active: boolean;
}
