// Types mirrored by hand from crates/raidian/proto/auth.proto and repository.proto.
// Keep in sync when the .proto changes.

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  display_name: string;
  avatar_url: string;
  bio: string;
  is_admin: boolean;
  created_at: number;
  updated_at: number;
}

export interface AuthResponse {
  token: string;
  user: UserProfile;
}

export interface LoginRequest {
  username_or_email: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  display_name: string;
}

export interface GithubOauthRequest {
  code: string;
  state: string;
}

export interface Repository {
  id: string;
  owner_id: string;
  owner_username: string;
  name: string;
  full_name: string;
  description: string;
  is_private: boolean;
  default_branch: string;
  created_at: number;
  updated_at: number;
}

export interface CreateRepositoryRequest {
  name: string;
  description: string;
  is_private: boolean;
}

export interface ApiErrorBody {
  error: string;
  message: string;
}
