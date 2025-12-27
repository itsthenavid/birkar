import 'dotenv/config';

import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';
import { Pool } from 'pg';

function requireEnv(name: string): string {
  const v = process.env[name];
  if (typeof v !== 'string' || v.trim() === '') {
    throw new Error(`${name} is missing in seed process env`);
  }
  return v;
}

const DATABASE_URL = requireEnv('DATABASE_URL');

const pool = new Pool({ connectionString: DATABASE_URL });
const adapter = new PrismaPg(pool);

const prisma = new PrismaClient({ adapter });

/**
 * Seed goals:
 * - Deterministic + idempotent (safe to re-run)
 * - Enterprise-grade RBAC scaffolding
 * - Optional bootstrap SUPERUSER (env-driven)
 * - argon2id password hashing
 *
 * Env:
 * - SEED_SUPERUSER_EMAIL
 * - SEED_SUPERUSER_USERNAME
 * - SEED_SUPERUSER_PASSWORD
 * - SEED_SUPERUSER_UPDATE_PASSWORD=true|false (optional)
 */

type RoleName = 'SUPERUSER' | 'USER' | 'WRITER';

const ROLES: ReadonlyArray<{ name: RoleName; description: string }> = [
  { name: 'SUPERUSER', description: 'Full access to everything.' },
  { name: 'USER', description: 'Default registered user.' },
  { name: 'WRITER', description: 'Approved writer (gated by owner).' },
];

const PERMISSIONS: ReadonlyArray<{ key: string; description: string }> = [
  { key: 'admin.access', description: 'Access admin/studio areas.' },
  { key: 'rbac.manage', description: 'Manage roles and permissions.' },

  { key: 'account.read_private', description: 'Read private account fields.' },
  { key: 'account.write', description: 'Edit own account/profile.' },

  { key: 'follow.write', description: 'Follow/unfollow users.' },

  { key: 'writer.approve', description: 'Approve/deny writer requests.' },
  { key: 'writer.invite', description: 'Create/revoke writer invites.' },

  { key: 'audit.read', description: 'Read audit logs.' },
];

const ROLE_PERMISSIONS: Readonly<Record<RoleName, ReadonlyArray<string>>> = {
  SUPERUSER: PERMISSIONS.map((p) => p.key),
  USER: ['account.write', 'follow.write'],
  WRITER: ['account.write', 'follow.write'],
};

const BADGES: ReadonlyArray<{
  key: string;
  label: string;
  description: string;
  icon?: string | null;
  color?: string | null;
}> = [
  {
    key: 'founder',
    label: 'Founder',
    description: 'Platform founder.',
    icon: 'sparkles',
    color: 'aurora',
  },
  {
    key: 'writer',
    label: 'Writer',
    description: 'Approved writer.',
    icon: 'feather',
    color: 'ink',
  },
  {
    key: 'early_supporter',
    label: 'Early Supporter',
    description: 'Supported early.',
    icon: 'heart',
    color: 'rose',
  },
];

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

function envBool(v: string | undefined): boolean {
  if (!v) return false;
  return ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase());
}

async function hashPasswordArgon2id(password: string): Promise<string> {
  // Dev-safe but still strong enough; tune per environment if you want
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456, // ~19MB
    timeCost: 2,
    parallelism: 1,
  });
}

async function reportCounts(): Promise<void> {
  const [
    roles,
    permissions,
    rolePermissions,
    badges,
    users,
    userRoles,
    userBadges,
    sessions,
    tokens,
    auditLogs,
  ] = await Promise.all([
    prisma.role.count(),
    prisma.permission.count(),
    prisma.rolePermission.count(),
    prisma.badge.count(),
    prisma.user.count(),
    prisma.userRole.count(),
    prisma.userBadge.count(),
    prisma.session.count(),
    prisma.authToken.count(),
    prisma.auditLog.count(),
  ]);

  console.log('\n— Seed state —');
  console.table({
    roles,
    permissions,
    rolePermissions,
    badges,
    users,
    userRoles,
    userBadges,
    sessions,
    tokens,
    auditLogs,
  });
}

async function main(): Promise<void> {
  console.log('🔧 Seeding Bîrkar (enterprise) ...');

  const seedResult = await prisma.$transaction(async (tx) => {
    // 1) Roles
    for (const r of ROLES) {
      await tx.role.upsert({
        where: { name: r.name },
        update: { description: r.description },
        create: { name: r.name, description: r.description },
      });
    }

    // 2) Permissions
    for (const p of PERMISSIONS) {
      await tx.permission.upsert({
        where: { key: p.key },
        update: { description: p.description },
        create: { key: p.key, description: p.description },
      });
    }

    // 3) Badges
    for (const b of BADGES) {
      await tx.badge.upsert({
        where: { key: b.key },
        update: {
          label: b.label,
          description: b.description,
          icon: b.icon ?? null,
          color: b.color ?? null,
        },
        create: {
          key: b.key,
          label: b.label,
          description: b.description,
          icon: b.icon ?? null,
          color: b.color ?? null,
        },
      });
    }

    // 4) Role <-> Permissions sync (idempotent)
    for (const roleName of Object.keys(ROLE_PERMISSIONS) as RoleName[]) {
      const role = await tx.role.findUnique({ where: { name: roleName } });
      if (!role) throw new Error(`Role missing: ${roleName}`);

      const desiredKeys = ROLE_PERMISSIONS[roleName];

      const perms = await tx.permission.findMany({
        where: { key: { in: [...desiredKeys] } },
        select: { id: true, key: true },
      });

      const foundKeys = new Set(perms.map((p) => p.key));
      const missing = desiredKeys.filter((k) => !foundKeys.has(k));
      if (missing.length) {
        throw new Error(
          `Missing permissions for role "${roleName}": ${missing.join(', ')}`,
        );
      }

      const desiredIds = new Set(perms.map((p) => p.id));

      const current = await tx.rolePermission.findMany({
        where: { roleId: role.id },
        select: { permissionId: true },
      });
      const currentIds = new Set(current.map((c) => c.permissionId));

      const toAdd = [...desiredIds].filter((id) => !currentIds.has(id));
      const toRemove = [...currentIds].filter((id) => !desiredIds.has(id));

      if (toAdd.length) {
        await tx.rolePermission.createMany({
          data: toAdd.map((permissionId) => ({
            roleId: role.id,
            permissionId,
          })),
          skipDuplicates: true,
        });
      }

      if (toRemove.length) {
        await tx.rolePermission.deleteMany({
          where: { roleId: role.id, permissionId: { in: toRemove } },
        });
      }
    }

    // 5) Optional bootstrap SUPERUSER
    const envEmail = process.env.SEED_SUPERUSER_EMAIL?.trim();
    const envUsername = process.env.SEED_SUPERUSER_USERNAME?.trim();
    const envPassword = process.env.SEED_SUPERUSER_PASSWORD?.trim();
    const updatePassword = envBool(process.env.SEED_SUPERUSER_UPDATE_PASSWORD);

    if (!envEmail || !envUsername || !envPassword) {
      return { bootstrapEnabled: false as const };
    }

    const email = normalizeEmail(envEmail);
    const username = normalizeUsername(envUsername);

    const superRole = await tx.role.findUnique({
      where: { name: 'SUPERUSER' },
    });
    if (!superRole)
      throw new Error('SUPERUSER role missing (seed order issue).');

    const existing = await tx.user.findFirst({
      where: { OR: [{ email }, { username }] },
      select: { id: true, email: true, username: true, passwordHash: true },
    });

    let userId: string;
    let created = false;

    if (!existing) {
      const passwordHash = await hashPasswordArgon2id(envPassword);

      const user = await tx.user.create({
        data: {
          email,
          username,
          passwordHash,
          emailVerifiedAt: new Date(),
          status: 'ACTIVE',
          profile: { create: { displayName: 'Founder', isPublic: true } },
        },
        select: { id: true },
      });

      userId = user.id;
      created = true;

      // Founder badge
      const founderBadge = await tx.badge.findUnique({
        where: { key: 'founder' },
      });
      if (founderBadge) {
        await tx.userBadge.upsert({
          where: { userId_badgeId: { userId, badgeId: founderBadge.id } },
          update: {},
          create: { userId, badgeId: founderBadge.id, assignedBy: userId },
        });
      }

      await tx.auditLog.create({
        data: {
          severity: 'SECURITY',
          action: 'AUTH_REGISTER',
          actorId: userId,
          meta: { bootstrap: true },
        },
      });
    } else {
      userId = existing.id;

      if (updatePassword) {
        const passwordHash = await hashPasswordArgon2id(envPassword);
        await tx.user.update({
          where: { id: userId },
          data: { passwordHash },
        });
      }
    }

    // Ensure SUPERUSER role assignment
    await tx.userRole.upsert({
      where: { userId_roleId: { userId, roleId: superRole.id } },
      update: {},
      create: { userId, roleId: superRole.id, assignedBy: userId },
    });

    return { bootstrapEnabled: true as const, userId, created };
  });

  console.log('✅ Seed completed.');
  if (!seedResult.bootstrapEnabled) {
    console.log(
      'ℹ️ Bootstrap SUPERUSER disabled. Set env vars SEED_SUPERUSER_EMAIL/USERNAME/PASSWORD to enable.',
    );
  } else if (seedResult.created) {
    console.log(
      `✅ Bootstrap SUPERUSER created (userId=${seedResult.userId}).`,
    );
  } else {
    console.log(
      `ℹ️ Bootstrap SUPERUSER ensured (userId=${seedResult.userId}).`,
    );
  }

  await reportCounts();
}

main()
  .catch((e: unknown) => {
    console.error('❌ Seed failed:', e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
