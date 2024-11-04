import mongoose, { Schema } from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";

const transactionSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    transactionType: {
      type: String,
      enum: ["Checking to Saving", "Saving to Checking","Checking to Saving (auto-sweep)"],
      required: true
    },
    transactionAmount: {
      type: String,
      required: true
    },
    transactionStatus: {
      type: String,
      enum: ["Pending", "Completed"],
      default: "Pending"
    }
  },
  {
    timestamps: true
  }
);

transactionSchema.plugin(mongooseAggregatePaginate);
export const Transaction = mongoose.model("Transaction", transactionSchema);
