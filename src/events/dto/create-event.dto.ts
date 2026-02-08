import {
  IsDateString,
  IsInt,
  IsNotEmpty,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { STRING_MAX_LENGTH } from 'src/constants/variables';

export class CreateEventDto {
  @ApiProperty({
    description: 'Event title',
    example: 'IEEE AI Workshop',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  title: string;

  @ApiProperty({
    description: 'Event description',
    example: 'A hands-on workshop on AI fundamentals and applications.',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(1000)
  description: string;

  @ApiProperty({
    description: 'Event location',
    example: 'Main Auditorium, Building B',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  location: string;

  @ApiProperty({
    description: 'Event start time (ISO 8601)',
    example: '2026-03-15T10:00:00Z',
  })
  @IsDateString()
  start_time: string;

  @ApiProperty({
    description: 'Event end time (ISO 8601)',
    example: '2026-03-15T12:00:00Z',
  })
  @IsDateString()
  end_time: string;

  @ApiProperty({
    description: 'Maximum number of attendees',
    example: 100,
    minimum: 1,
  })
  @IsInt()
  @Min(1)
  capacity: number;

  @ApiProperty({
    description: 'Registration deadline (ISO 8601)',
    example: '2026-03-10T23:59:59Z',
  })
  @IsDateString()
  registration_deadline: string;
}
