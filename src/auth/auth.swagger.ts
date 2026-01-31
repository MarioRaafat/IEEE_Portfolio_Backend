import { SUCCESS_MESSAGES } from '../constants/swagger-messages';

const user_example = {
  id: 'd102dadc-0b17-4e83-812b-00103b606a1f',
  email: 'mariorafat10@gmail.com',
  username: 'MarioRaafat',
  name: 'Mario Raafat',
  faculty: 'Engineering',
  university: 'Cairo University',
  academic_year: 3,
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

export const register_swagger = {
  operation: {
    summary: 'User registration',
    description:
      'Register a new user with email, username, name, faculty, university, academic year, and password.',
  },
  responses: {
    success: {
      description: 'User registered successfully',
      schema: {
        example: {
          data: {
            user: {
              ...user_example,
            },
          },
          count: 1,
          message: SUCCESS_MESSAGES.USER_REGISTERED,
        },
      },
    },
  },
};

export const logout_swagger = {
  operation: {
    summary: 'User logout',
    description: 'Logout user and clear refresh token cookie.',
  },
  responses: {
    success: {
      description: 'Logout successful',
      schema: {
        example: {
          data: {},
          count: 0,
          message: SUCCESS_MESSAGES.LOGGED_OUT,
        },
      },
    },
  },
};

export const generate_otp_swagger = {
  operation: {
    summary: 'Generate OTP',
    description: 'Generate and send OTP code to user email for verification.',
  },
  responses: {
    success: {
      description: 'OTP generated and sent successfully',
      schema: {
        example: {
          data: {},
          count: 0,
          message: SUCCESS_MESSAGES.OTP_GENERATED,
        },
      },
    },
  },
};

export const verify_otp_swagger = {
  operation: {
    summary: 'Verify OTP',
    description: 'Verify OTP code for email verification or password reset.',
  },
  responses: {
    success: {
      description: 'OTP verified successfully',
      schema: {
        example: {
          data: {},
          count: 0,
          message: SUCCESS_MESSAGES.OTP_VERIFIED,
        },
      },
    },
  },
};

export const send_email_otp_swagger = {
  operation: {
    summary: 'Send email verification OTP',
    description: 'Send OTP code to verify user email address.',
  },
  responses: {
    success: {
      description: 'OTP generated and sent successfully',
      schema: {
        example: {
          data: {},
          count: 0,
          message: SUCCESS_MESSAGES.OTP_GENERATED,
        },
      },
    },
  },
};

export const verify_email_otp_swagger = {
  operation: {
    summary: 'Verify email OTP',
    description: 'Verify OTP code to confirm email address.',
  },
  responses: {
    success: {
      description: 'Email verified successfully',
      schema: {
        example: {
          data: {},
          count: 0,
          message: SUCCESS_MESSAGES.EMAIL_VERIFIED,
        },
      },
    },
  },
};

export const send_password_reset_otp_swagger = {
  operation: {
    summary: 'Send password reset OTP',
    description: 'Send OTP code for password reset.',
  },
  responses: {
    success: {
      description: 'Password reset OTP sent successfully',
      schema: {
        example: {
          data: {},
          count: 0,
          message: SUCCESS_MESSAGES.PASSWORD_RESET_OTP_SENT,
        },
      },
    },
  },
};

export const reset_password_swagger = {
  operation: {
    summary: 'Reset password with OTP',
    description: 'Verify OTP and reset the user password.',
  },
  responses: {
    success: {
      description: 'Password reset successfully',
      schema: {
        example: {
          data: {},
          count: 0,
          message: SUCCESS_MESSAGES.PASSWORD_RESET,
        },
      },
    },
  },
};

export const change_password_swagger = {
  operation: {
    summary: 'Change password',
    description: 'Change the current user password using the old password.',
  },
  responses: {
    success: {
      description: 'Password changed successfully',
      schema: {
        example: {
          data: {},
          count: 0,
          message: SUCCESS_MESSAGES.PASSWORD_CHANGED,
        },
      },
    },
  },
};
