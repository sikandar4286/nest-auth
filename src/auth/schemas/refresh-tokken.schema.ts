import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

@Schema({ versionKey: false, timestamps: true })
export class RefrechToken extends Document {
  @Prop({ required: true })
  token: string;

  @Prop({ required: true, type: mongoose.Types.ObjectId })
  userId: string;

  @Prop({ required: true })
  expireyDate: Date;
}

export const RefrechTokenSchema = SchemaFactory.createForClass(RefrechToken);
