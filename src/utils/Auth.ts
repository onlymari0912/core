import bcrypt from 'bcryptjs';

const BCRYPT_PREFIXES = ['$2a$', '$2b$', '$2y$'];
const SALT_ROUNDS = 12;

export function isBcryptHash(value: string) {
  if (typeof value !== 'string') return false;
  return BCRYPT_PREFIXES.some(prefix => value.startsWith(prefix));
}

export async function hashPassword(plain: string) {
  return await bcrypt.hash(plain, SALT_ROUNDS);
}

export async function verifyPassword(plain: string, stored: string) {
  if (isBcryptHash(stored)) {
    return await bcrypt.compare(plain, stored);
  }
  return plain === stored;
}
