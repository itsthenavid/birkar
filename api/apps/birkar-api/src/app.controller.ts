import { Controller, Get, UseGuards } from '@nestjs/common';
import { DevImpersonateGuard } from './common/guards/dev-impersonate.guard';
import { RequirePermissions } from './modules/rbac/permissions.decorator';
import { PermissionsGuard } from './modules/rbac/permissions.guard';

@Controller()
export class AppController {
  @Get('/health')
  health() {
    return { ok: true };
  }

  @Get('/admin/ping')
  @UseGuards(DevImpersonateGuard, PermissionsGuard)
  @RequirePermissions('admin.access')
  adminPing() {
    return { ok: true, scope: 'admin.access' };
  }
}
