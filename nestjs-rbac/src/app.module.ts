import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { NotesController } from './notes.controller';
import { AuthGuard } from './auth.guard';
import { RolesGuard } from './roles.guard';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET ?? 'local-task-5-secret',
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController, NotesController],
  providers: [AuthGuard, RolesGuard],
})
export class AppModule {}
