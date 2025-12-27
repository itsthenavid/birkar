import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../infra/prisma/prisma.service';

@Injectable()
export class RbacService {
  constructor(private readonly prisma: PrismaService) {}

  async getUserPermissionKeys(userId: string): Promise<Set<string>> {
    const roles = await this.prisma.userRole.findMany({
      where: { userId },
      select: {
        role: {
          select: {
            permissions: {
              select: {
                permission: { select: { key: true } },
              },
            },
          },
        },
      },
    });

    const keys = new Set<string>();
    for (const r of roles) {
      for (const rp of r.role.permissions) {
        keys.add(rp.permission.key);
      }
    }
    return keys;
  }
}
