
import { SUCCESS_MESSAGES } from '../constants/swagger-messages';

const user_example = {
    id: 'd102dadc-0b17-4e83-812b-00103b606a1f',
    email: 'mariorafat10@gmail.com',
    name: 'Mario Raafat',
    phone_number: '+201204878505',
    github_id: null,
    google_id: null,
    avatar_url: null,
};

export const login_swagger = {
    operation: {
        summary: 'User login',
        description:
            'Authenticate user and receive access token. Refresh token is set as httpOnly cookie.',
    },

    responses: {
        success: {
            description: 'Login successful',
            schema: {
                example: {
                    data: {
                        access_token:
                            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImQxMDJkYWRjLTBiMTctNGU4My04MTJiLTAwMTAzYjYwNmExZiIsImlhdCI6MTc1ODE0Nzg2OSwiZXhwIjoxNzU4MTUxNDY5fQ.DV3oA5Fn-cj-KHrGcafGaoWGyvYFx4N50L9Ke4_n6OU',
                        user: {
                            ...user_example,
                        },
                    },
                    count: 1,
                    message: SUCCESS_MESSAGES.LOGGED_IN,
                },
            },
            headers: {
                'Set-Cookie': {
                    description: 'HttpOnly cookie containing refresh token',
                    schema: {
                        type: 'string',
                        example:
                            'refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly; Secure; SameSite=Strict',
                    },
                },
            },
        },
    },
};
