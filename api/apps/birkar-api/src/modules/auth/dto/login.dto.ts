import { z } from 'zod';

export const LoginSchema = z.object({
  identifier: z.string().min(3).max(200), // username or email
  password: z.string().min(1).max(200),
  rotate: z.boolean().optional(),
});

export type LoginDto = z.infer<typeof LoginSchema>;
