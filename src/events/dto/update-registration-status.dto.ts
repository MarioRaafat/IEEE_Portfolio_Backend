import { ApiProperty } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';
import { EventRegistrationStatus } from '../entities/event-registration.entity';

export class UpdateRegistrationStatusDto {
  @ApiProperty({
    description: 'Registration status',
    enum: EventRegistrationStatus,
    example: EventRegistrationStatus.ATTENDED,
  })
  @IsEnum(EventRegistrationStatus)
  status: EventRegistrationStatus;
}
