import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { Event } from './entities/event.entity';
import {
  EventRegistration,
  EventRegistrationStatus,
} from './entities/event-registration.entity';
import { CreateEventDto } from './dto/create-event.dto';
import { UpdateEventDto } from './dto/update-event.dto';
import { User } from 'src/users/entities/user.entity';
import { RoleName } from 'src/roles/entities/role.entity';
import { ERROR_MESSAGES } from 'src/constants/swagger-messages';

@Injectable()
export class EventsService {
  constructor(
    @InjectRepository(Event)
    private readonly eventsRepository: Repository<Event>,
    @InjectRepository(EventRegistration)
    private readonly registrationsRepository: Repository<EventRegistration>,
  ) {}

  private ensureAdmin(currentUser: User) {
    if (
      currentUser.role.name !== RoleName.SUPER_ADMIN &&
      currentUser.role.name !== RoleName.ADMIN
    ) {
      throw new ForbiddenException(ERROR_MESSAGES.FORBIDDEN_ACTION);
    }
  }

  private validateEventTimes(
    start_time: Date,
    end_time: Date,
    registration_deadline: Date,
  ) {
    if (start_time >= end_time) {
      throw new BadRequestException(ERROR_MESSAGES.EVENT_INVALID_TIME_RANGE);
    }

    if (registration_deadline > start_time) {
      throw new BadRequestException(ERROR_MESSAGES.EVENT_INVALID_TIME_RANGE);
    }
  }

  async create(createEventDto: CreateEventDto, currentUser: User) {
    this.ensureAdmin(currentUser);

    const start_time = new Date(createEventDto.start_time);
    const end_time = new Date(createEventDto.end_time);
    const registration_deadline = new Date(
      createEventDto.registration_deadline,
    );

    this.validateEventTimes(start_time, end_time, registration_deadline);

    const event = this.eventsRepository.create({
      ...createEventDto,
      start_time,
      end_time,
      registration_deadline,
      created_by: currentUser.id,
    });

    return this.eventsRepository.save(event);
  }

  async findAll(page: number = 1, limit: number = 10) {
    const skip = (page - 1) * limit;

    const [events, total] = await this.eventsRepository.findAndCount({
      skip,
      take: limit,
      order: { start_time: 'ASC' },
    });

    return {
      data: events,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async findOne(id: string) {
    const event = await this.eventsRepository.findOne({
      where: { id },
    });

    if (!event) {
      throw new NotFoundException(ERROR_MESSAGES.EVENT_NOT_FOUND);
    }

    return event;
  }

  async update(id: string, updateEventDto: UpdateEventDto, currentUser: User) {
    this.ensureAdmin(currentUser);

    const event = await this.eventsRepository.preload({
      id,
      ...updateEventDto,
      start_time: updateEventDto.start_time
        ? new Date(updateEventDto.start_time)
        : undefined,
      end_time: updateEventDto.end_time
        ? new Date(updateEventDto.end_time)
        : undefined,
      registration_deadline: updateEventDto.registration_deadline
        ? new Date(updateEventDto.registration_deadline)
        : undefined,
    });

    if (!event) {
      throw new NotFoundException(ERROR_MESSAGES.EVENT_NOT_FOUND);
    }

    if (event.start_time && event.end_time && event.registration_deadline) {
      this.validateEventTimes(
        event.start_time,
        event.end_time,
        event.registration_deadline,
      );
    }

    return this.eventsRepository.save(event);
  }

  async remove(id: string, currentUser: User) {
    this.ensureAdmin(currentUser);

    const result = await this.eventsRepository.delete(id);

    if (result.affected === 0) {
      throw new NotFoundException(ERROR_MESSAGES.EVENT_NOT_FOUND);
    }

    return { message: 'Event deleted successfully' };
  }

  async register(eventId: string, currentUser: User) {
    const event = await this.findOne(eventId);

    if (new Date() > event.registration_deadline) {
      throw new BadRequestException(ERROR_MESSAGES.EVENT_REGISTRATION_CLOSED);
    }

    const existingRegistration = await this.registrationsRepository.findOne({
      where: { event_id: eventId, user_id: currentUser.id },
    });

    if (
      existingRegistration &&
      existingRegistration.status !== EventRegistrationStatus.CANCELLED
    ) {
      throw new ConflictException(ERROR_MESSAGES.EVENT_ALREADY_REGISTERED);
    }

    const registeredCount = await this.registrationsRepository.count({
      where: {
        event_id: eventId,
        status: In([
          EventRegistrationStatus.REGISTERED,
          EventRegistrationStatus.ATTENDED,
        ]),
      },
    });

    const status =
      registeredCount >= event.capacity
        ? EventRegistrationStatus.WAITLISTED
        : EventRegistrationStatus.REGISTERED;

    if (existingRegistration) {
      existingRegistration.status = status;
      return this.registrationsRepository.save(existingRegistration);
    }

    const registration = this.registrationsRepository.create({
      event_id: eventId,
      user_id: currentUser.id,
      status,
    });

    return this.registrationsRepository.save(registration);
  }

  async cancelRegistration(eventId: string, currentUser: User) {
    const registration = await this.registrationsRepository.findOne({
      where: { event_id: eventId, user_id: currentUser.id },
    });

    if (!registration) {
      throw new NotFoundException(ERROR_MESSAGES.EVENT_REGISTRATION_NOT_FOUND);
    }

    if (registration.status !== EventRegistrationStatus.CANCELLED) {
      registration.status = EventRegistrationStatus.CANCELLED;
      await this.registrationsRepository.save(registration);

      const [waitlisted] = await this.registrationsRepository.find({
        where: {
          event_id: eventId,
          status: EventRegistrationStatus.WAITLISTED,
        },
        order: { created_at: 'ASC' },
        take: 1,
      });

      if (waitlisted) {
        waitlisted.status = EventRegistrationStatus.REGISTERED;
        await this.registrationsRepository.save(waitlisted);
      }
    }

    return registration;
  }

  async getEventRegistrations(
    eventId: string,
    currentUser: User,
    page: number = 1,
    limit: number = 10,
  ) {
    this.ensureAdmin(currentUser);

    await this.findOne(eventId);

    const skip = (page - 1) * limit;

    const [registrations, total] =
      await this.registrationsRepository.findAndCount({
        where: { event_id: eventId },
        relations: ['user'],
        skip,
        take: limit,
        order: { created_at: 'DESC' },
      });

    return {
      data: registrations,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async updateRegistrationStatus(
    eventId: string,
    registrationId: string,
    status: EventRegistrationStatus,
    currentUser: User,
  ) {
    this.ensureAdmin(currentUser);

    const registration = await this.registrationsRepository.findOne({
      where: { id: registrationId, event_id: eventId },
    });

    if (!registration) {
      throw new NotFoundException(ERROR_MESSAGES.EVENT_REGISTRATION_NOT_FOUND);
    }

    if (
      status === EventRegistrationStatus.REGISTERED &&
      registration.status !== EventRegistrationStatus.REGISTERED
    ) {
      const event = await this.findOne(eventId);
      const registeredCount = await this.registrationsRepository.count({
        where: {
          event_id: eventId,
          status: In([
            EventRegistrationStatus.REGISTERED,
            EventRegistrationStatus.ATTENDED,
          ]),
        },
      });

      if (registeredCount >= event.capacity) {
        throw new BadRequestException(ERROR_MESSAGES.EVENT_FULL);
      }
    }

    registration.status = status;

    return this.registrationsRepository.save(registration);
  }
}
