import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';
import { EventsService } from './events.service';
import { CreateEventDto } from './dto/create-event.dto';
import { UpdateEventDto } from './dto/update-event.dto';
import { UpdateRegistrationStatusDto } from './dto/update-registration-status.dto';
import {
  ApiBadRequestErrorResponse,
  ApiConflictErrorResponse,
  ApiForbiddenErrorResponse,
  ApiInternalServerError,
  ApiNotFoundErrorResponse,
  ApiUnauthorizedErrorResponse,
} from 'src/decorators/swagger-error-responses.decorator';
import {
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
} from 'src/constants/swagger-messages';
import {
  cancel_event_registration_swagger,
  create_event_swagger,
  delete_event_swagger,
  get_all_events_swagger,
  get_event_by_id_swagger,
  get_event_registrations_swagger,
  register_event_swagger,
  update_event_registration_status_swagger,
  update_event_swagger,
} from './events.swagger';
import { ResponseMessage } from 'src/decorators/response-message.decorator';
import { User } from 'src/users/entities/user.entity';

@ApiTags('events')
@Controller('events')
export class EventsController {
  constructor(private readonly eventsService: EventsService) {}

  @UseGuards(AuthGuard('jwt'))
  @Post()
  @ApiBearerAuth()
  @ApiOperation(create_event_swagger.operation)
  @ApiCreatedResponse(create_event_swagger.responses.success)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiForbiddenErrorResponse(ERROR_MESSAGES.FORBIDDEN_ACTION)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.EVENT_INVALID_TIME_RANGE)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  @ResponseMessage(SUCCESS_MESSAGES.EVENT_CREATED)
  create(
    @Body() createEventDto: CreateEventDto,
    @Req() req: Request & { user: User },
  ) {
    return this.eventsService.create(createEventDto, req.user);
  }

  @Get()
  @ApiOperation(get_all_events_swagger.operation)
  @ApiOkResponse(get_all_events_swagger.responses.success)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  findAll(
    @Query('page') page: string = '1',
    @Query('limit') limit: string = '10',
  ) {
    return this.eventsService.findAll(parseInt(page), parseInt(limit));
  }

  @Get(':id')
  @ApiOperation(get_event_by_id_swagger.operation)
  @ApiOkResponse(get_event_by_id_swagger.responses.success)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.EVENT_NOT_FOUND)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  findOne(@Param('id', ParseUUIDPipe) id: string) {
    return this.eventsService.findOne(id);
  }

  @UseGuards(AuthGuard('jwt'))
  @Patch(':id')
  @ApiBearerAuth()
  @ApiOperation(update_event_swagger.operation)
  @ApiOkResponse(update_event_swagger.responses.success)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiForbiddenErrorResponse(ERROR_MESSAGES.FORBIDDEN_ACTION)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.EVENT_INVALID_TIME_RANGE)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.EVENT_NOT_FOUND)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  @ResponseMessage(SUCCESS_MESSAGES.EVENT_UPDATED)
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateEventDto: UpdateEventDto,
    @Req() req: Request & { user: User },
  ) {
    return this.eventsService.update(id, updateEventDto, req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete(':id')
  @ApiBearerAuth()
  @ApiOperation(delete_event_swagger.operation)
  @ApiOkResponse(delete_event_swagger.responses.success)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiForbiddenErrorResponse(ERROR_MESSAGES.FORBIDDEN_ACTION)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.EVENT_NOT_FOUND)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  @ResponseMessage(SUCCESS_MESSAGES.EVENT_DELETED)
  remove(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: Request & { user: User },
  ) {
    return this.eventsService.remove(id, req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post(':id/register')
  @ApiBearerAuth()
  @ApiOperation(register_event_swagger.operation)
  @ApiOkResponse(register_event_swagger.responses.success)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.EVENT_REGISTRATION_CLOSED)
  @ApiConflictErrorResponse(ERROR_MESSAGES.EVENT_ALREADY_REGISTERED)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.EVENT_NOT_FOUND)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  @ResponseMessage(SUCCESS_MESSAGES.EVENT_REGISTERED)
  register(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: Request & { user: User },
  ) {
    return this.eventsService.register(id, req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Patch(':id/cancel')
  @ApiBearerAuth()
  @ApiOperation(cancel_event_registration_swagger.operation)
  @ApiOkResponse(cancel_event_registration_swagger.responses.success)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.EVENT_REGISTRATION_NOT_FOUND)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  @ResponseMessage(SUCCESS_MESSAGES.EVENT_REGISTRATION_CANCELLED)
  cancelRegistration(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: Request & { user: User },
  ) {
    return this.eventsService.cancelRegistration(id, req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get(':id/registrations')
  @ApiBearerAuth()
  @ApiOperation(get_event_registrations_swagger.operation)
  @ApiOkResponse(get_event_registrations_swagger.responses.success)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiForbiddenErrorResponse(ERROR_MESSAGES.FORBIDDEN_ACTION)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.EVENT_NOT_FOUND)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  getEventRegistrations(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: Request & { user: User },
    @Query('page') page: string = '1',
    @Query('limit') limit: string = '10',
  ) {
    return this.eventsService.getEventRegistrations(
      id,
      req.user,
      parseInt(page),
      parseInt(limit),
    );
  }

  @UseGuards(AuthGuard('jwt'))
  @Patch(':id/registrations/:registrationId/status')
  @ApiBearerAuth()
  @ApiOperation(update_event_registration_status_swagger.operation)
  @ApiOkResponse(update_event_registration_status_swagger.responses.success)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiForbiddenErrorResponse(ERROR_MESSAGES.FORBIDDEN_ACTION)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.EVENT_FULL)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.EVENT_REGISTRATION_NOT_FOUND)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  @ResponseMessage(SUCCESS_MESSAGES.EVENT_REGISTRATION_STATUS_UPDATED)
  updateRegistrationStatus(
    @Param('id', ParseUUIDPipe) id: string,
    @Param('registrationId', ParseUUIDPipe) registrationId: string,
    @Body() updateStatusDto: UpdateRegistrationStatusDto,
    @Req() req: Request & { user: User },
  ) {
    return this.eventsService.updateRegistrationStatus(
      id,
      registrationId,
      updateStatusDto.status,
      req.user,
    );
  }
}
