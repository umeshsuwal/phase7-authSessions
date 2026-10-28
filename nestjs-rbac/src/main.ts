import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3001, '127.0.0.1');
  console.log('NestJS RBAC API running at http://localhost:3001');
}

void bootstrap();
