export interface User {
  id: string;
  email: string;
  username: string;
  // password is optional on returned objects, present only on stored records
  password?: string;
  isEmailVerified?: boolean;
  createdAt?: string;
  updatedAt?: string;
  roles?: string[];
  phoneNumber?: string | null;
  avatarUrl?: string | null;
}
