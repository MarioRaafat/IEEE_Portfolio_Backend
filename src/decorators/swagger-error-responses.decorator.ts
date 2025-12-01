import { applyDecorators } from '@nestjs/common';
import {
    ApiBadRequestResponse,
    ApiConflictResponse,
    ApiForbiddenResponse,
    ApiInternalServerErrorResponse,
    ApiNotFoundResponse,
    ApiUnauthorizedResponse,
    ApiUnprocessableEntityResponse,
} from '@nestjs/swagger';

export const ApiBadRequestErrorResponse = (message: string) => {
    return applyDecorators(
        ApiBadRequestResponse({
            description: 'Bad Request',
            example: {
                message: message,
                error: 'Bad Request',
                status_code: 400,
            },
        })
    );
};

export const ApiUnauthorizedErrorResponse = (message: string) => {
    return applyDecorators(
        ApiUnauthorizedResponse({
            description: 'Unauthorized',
            example: {
                message: message,
                error: 'Unauthorized',
                status_code: 401,
            },
        })
    );
};

export const ApiForbiddenErrorResponse = (message: string) => {
    return applyDecorators(
        ApiForbiddenResponse({
            description: 'Forbidden',
            example: {
                message: message,
                error: 'Forbidden',
                status_code: 403,
            },
        })
    );
};

export const ApiNotFoundErrorResponse = (message: string) => {
    return applyDecorators(
        ApiNotFoundResponse({
            description: 'Not Found',
            example: {
                message: message,
                error: 'Not Found',
                status_code: 404,
            },
        })
    );
};

export const ApiConflictErrorResponse = (message: string) => {
    return applyDecorators(
        ApiConflictResponse({
            description: 'Conflict',
            example: {
                message: message,
                error: 'Conflict',
                status_code: 409,
            },
        })
    );
};

export const ApiUnprocessableEntityErrorResponse = (message: string) => {
    return applyDecorators(
        ApiUnprocessableEntityResponse({
            description: 'Unprocessable Entity',
            example: {
                message: message,
                error: 'Unprocessable Entity',
                status_code: 422,
            },
        })
    );
};

export const ApiInternalServerError = (message: string) => {
    return applyDecorators(
        ApiInternalServerErrorResponse({
            description: 'Internal Server Error',
            example: {
                message: message,
                error: 'Internal Server Error',
                status_code: 500,
            },
        })
    );
};
