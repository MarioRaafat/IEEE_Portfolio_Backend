import { User } from '../../users/entities/user.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  Unique,
} from 'typeorm';
import { Event } from './event.entity';

export enum EventRegistrationStatus {
  REGISTERED = 'registered',
  CANCELLED = 'cancelled',
  ATTENDED = 'attended',
  WAITLISTED = 'waitlisted',
}

@Entity('event_registrations')
@Unique('UQ_event_registration_unique', ['event_id', 'user_id'])
export class EventRegistration {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column('uuid')
  user_id: string;

  @ManyToOne(() => User, {
    nullable: false,
    onUpdate: 'CASCADE',
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column('uuid')
  event_id: string;

  @ManyToOne(() => Event, (event) => event.registrations, {
    nullable: false,
    onUpdate: 'CASCADE',
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'event_id' })
  event: Event;

  @Column({
    type: 'enum',
    enum: EventRegistrationStatus,
    default: EventRegistrationStatus.REGISTERED,
  })
  status: EventRegistrationStatus;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}
