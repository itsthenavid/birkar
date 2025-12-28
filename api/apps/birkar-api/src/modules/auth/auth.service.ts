import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import {
  looksLikeEmail,
  normalizeEmail,
  normalizeUsername,
} from '../../common/utils/normalize';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  async register(input: { username: string; email: string; password: string }) {
    const email = normalizeEmail(input.email);
    const username = normalizeUsername(input.username);

    const exists = await this.prisma.user.findFirst({
      where: { OR: [{ email }, { username }] },
      select: { id: true },
    });
    if (exists)
      throw new BadRequestException('Username or email already exists');

    const passwordHash = await argon2.hash(input.password, {
      type: argon2.argon2id,
    });

    const user = await this.prisma.user.create({
      data: {
        email,
        username,
        passwordHash,
        status: 'ACTIVE',
        profile: { create: { displayName: username, isPublic: true } },
      },
      select: { id: true, email: true, username: true },
    });

    const role = await this.prisma.role.findUnique({
      where: { name: 'USER' },
      select: { id: true },
    });
    if (role) {
      await this.prisma.userRole.upsert({
        where: { userId_roleId: { userId: user.id, roleId: role.id } },
        update: {},
        create: { userId: user.id, roleId: role.id, assignedBy: user.id },
      });
    }

    return user;
  }

  async validateLocal(identifier: string, password: string) {
    const normalized = identifier.trim().toLowerCase();

    const user = await this.prisma.user.findFirst({
      where: looksLikeEmail(normalized)
        ? { email: normalized }
        : { username: normalizeUsername(normalized) },
      select: { id: true, passwordHash: true, status: true },
    });

    if (!user || !user.passwordHash)
      throw new UnauthorizedException('Invalid credentials');
    if (user.status !== 'ACTIVE')
      throw new UnauthorizedException('User disabled');

    const ok = await argon2.verify(user.passwordHash, password);
    if (!ok) throw new UnauthorizedException('Invalid credentials');

    return { id: user.id };
  }

  async me(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        username: true,
        emailVerifiedAt: true,
        status: true,
        profile: {
          select: {
            displayName: true,
            location: true,
            website: true,
            isPublic: true,
          },
        },
      },
    });
  }
}
