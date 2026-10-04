import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(
    {
      error: "ZeroDivisionError",
      message: "division by zero in payment_processing_engine.py at line 142",
      stack_trace: `Traceback (most recent call last):
  File "payment_processing_engine.py", line 142, in process_transaction
    fee_ratio = total_amount / batch_count
ZeroDivisionError: division by zero`,
    },
    { status: 500 }
  );
}
