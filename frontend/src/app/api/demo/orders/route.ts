import { NextRequest, NextResponse } from "next/server";

let orders: any[] = [
  { order_id: 101, user_id: 1, amount: 499.99, currency: "USD", status: "COMPLETED" },
  { order_id: 102, user_id: 2, amount: 29.5, currency: "USD", status: "PENDING" },
];

export async function GET() {
  return NextResponse.json(orders);
}

export async function POST(request: NextRequest) {
  const data = await request.json().catch(() => ({}));
  const newId = orders.length > 0 ? Math.max(...orders.map((o) => o.order_id)) + 1 : 101;
  const order = {
    order_id: newId,
    user_id: data.user_id || 1,
    amount: data.amount || 0.0,
    currency: data.currency || "USD",
    status: "PROCESSED",
  };
  orders.push(order);
  return NextResponse.json(order, { status: 201 });
}
