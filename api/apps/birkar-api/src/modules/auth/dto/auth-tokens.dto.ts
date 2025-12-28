// src/modules/auth/dto/tokens.dto.ts
import { z } from 'zod';

export const VerifyEmailRequestSchema = z.object({
  email: z.string().email().optional(),
});
export type VerifyEmailRequestDto = z.infer<typeof VerifyEmailRequestSchema>;

export const VerifyEmailConfirmSchema = z.object({
  token: z.string().min(10).max(500),
});
export type VerifyEmailConfirmDto = z.infer<typeof VerifyEmailConfirmSchema>;

export const PasswordResetRequestSchema = z.object({
  identifier: z.string().min(3).max(200),
});
export type PasswordResetRequestDto = z.infer<
  typeof PasswordResetRequestSchema
>;

export const PasswordResetConfirmSchema = z.object({
  token: z.string().min(10).max(500),
  newPassword: z.string().min(8).max(200),
});
export type PasswordResetConfirmDto = z.infer<
  typeof PasswordResetConfirmSchema
>;
