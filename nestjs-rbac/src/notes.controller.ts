import {
  Controller,
  Delete,
  Get,
  Param,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from './auth.guard';
import { Roles } from './roles.decorator';
import { RolesGuard } from './roles.guard';

const notes = [
  { id: 1, title: 'RBAC notes', body: 'Server-side authorization' },
  { id: 2, title: 'Guard order', body: 'Authenticate before authorizing' },
];

@Controller('notes')
@UseGuards(AuthGuard, RolesGuard)
export class NotesController {
  @Get()
  @Roles('admin', 'user')
  findAll() {
    return notes;
  }

  @Delete(':id')
  @Roles('admin')
  remove(@Param('id') id: string) {
    const index = notes.findIndex((note) => note.id === Number(id));
    if (index === -1) {
      return { message: 'Note not found' };
    }

    const [deleted] = notes.splice(index, 1);
    return { message: 'Note deleted', note: deleted };
  }
}
