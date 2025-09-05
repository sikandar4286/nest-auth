import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { Resource } from '../enums/resource.enum';
import { Action } from '../enums/action.enum';

@Schema({ versionKey: false, timestamps: true })
class RolePermission {
  @Prop({ required: true, enum: Resource, type: String })
  resource: Resource | string;

  @Prop({ required: true, type: [String], enum: Object.values(Action) })
  actions: Action[] | string[];
}

@Schema({ versionKey: false, timestamps: true })
export class Role extends Document {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, type: [RolePermission] })
  permissions: RolePermission[];
}

export const RoleSchema = SchemaFactory.createForClass(Role);
