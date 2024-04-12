// alert.controller.ts

import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Body,
  Patch,
} from '@nestjs/common';
import { AlertService } from './alert.service';
import { Alert } from './alert.entity';
import { CreateAlertDto } from './dto/create-alert.dto';
import { UpdateAlertDto } from './dto/update-alert.dto';



@Controller('alerts')
export class AlertController {
  constructor(private readonly alertService: AlertService) {}

  @Get()
  async findAll(): Promise<Alert[]> {
    return this.alertService.findAll();
  }


  @Get(':id')
  async findById(@Param('id') id: number): Promise<Alert> {
    return this.alertService.findById(id);
  }

  @Post()
  async create(@Body() createAlertDto: CreateAlertDto): Promise<Alert> {
    return this.alertService.create(createAlertDto);
  }

  @Patch(':id')
  async update(
    @Param('id') id: number,
    @Body() updateAlertDto: UpdateAlertDto,
  ): Promise<Alert> {
    return this.alertService.update(id, updateAlertDto);
  }

  @Delete(':id')
  async delete(@Param('id') id: number): Promise<void> {
    return this.alertService.delete(id);
  }
}
