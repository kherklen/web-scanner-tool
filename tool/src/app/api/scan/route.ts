import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  const body = await req.json();
  const { url } = body;

  if (!url) {
    return NextResponse.json({ error: 'URL is required' }, { status: 400 });
  }

  try {
    // Make a request to your Python backend (assuming it's running on http://localhost:5000)
    const response = await fetch('http://localhost:5000/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error('Failed to scan the website');
    }

    const scanResults = await response.json();
    return NextResponse.json(scanResults);  // Return the results from the Python backend

  } catch (error) {
    console.error('Error while scanning:', error);
    return NextResponse.json({ error: 'Failed to scan the website' }, { status: 500 });
  }
}
