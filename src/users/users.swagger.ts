import { SUCCESS_MESSAGES } from '../constants/swagger-messages';

const user_example = {
  id: 'd102dadc-0b17-4e83-812b-00103b606a1f',
  name: 'Ali Said',
  email: 'asaszizg1@gmail.com',
  phone: '+201001234567',
  avatar_url: 'https://example.com/avatars/AliSaid.jpg',
  bio: 'Computer Science student interested in AI and web development',
  faculty: 'Faculty of Engineering',
  university: 'Cairo University',
  academic_year: 3,
  major: 'Computer Engineering',
  role_id: '550e8400-e29b-41d4-a716-446655440000',
  created_at: '2025-12-03T10:30:00Z',
  updated_at: '2025-12-03T10:30:00Z',
};

export const create_user_swagger = {
  operation: {
    summary: 'Create a new user',
    description:
      'Create a new user account with email, password, and profile information.',
  },

  responses: {
    success: {
      description: 'User created successfully',
      schema: {
        example: {
          data: {
            ...user_example,
          },
          count: 1,
          message: SUCCESS_MESSAGES.USER_REGISTERED,
        },
      },
    },
  },
};

export const get_user_by_id_swagger = {
  operation: {
    summary: 'Get user by ID',
    description: 'Retrieve a specific user by their unique ID.',
  },

  responses: {
    success: {
      description: 'User retrieved successfully',
      schema: {
        example: {
          data: {
            ...user_example,
          },
          count: 1,
          message: 'User retrieved successfully',
        },
      },
    },
  },
};

export const update_user_swagger = {
  operation: {
    summary: 'Update user',
    description: 'Update user profile information and details.',
  },

  responses: {
    success: {
      description: 'User updated successfully',
      schema: {
        example: {
          data: {
            ...user_example,
            updated_at: '2025-12-03T15:45:00Z',
          },
          count: 1,
          message: 'User updated successfully',
        },
      },
    },
  },
};

export const delete_user_swagger = {
  operation: {
    summary: 'Delete user',
    description: 'Delete a user account and all associated data.',
  },

  responses: {
    success: {
      description: 'User deleted successfully',
      schema: {
        example: {
          data: {
            id: user_example.id,
          },
          count: 1,
          message: 'User deleted successfully',
        },
      },
    },
  },
};
