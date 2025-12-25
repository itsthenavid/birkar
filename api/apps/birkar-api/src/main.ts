import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ? Number(process.env.PORT) : 3001);
}

bootstrap().catch((err) => {
  console.error('Nest application failed to start', err);
  process.exit(1);
});
