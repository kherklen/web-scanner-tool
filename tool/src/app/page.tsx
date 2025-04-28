import { useState } from 'react';
import Scanner from '../components/scanner';

export default function Page() {

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-6">
      <div className="max-w-xl w-full bg-white rounded-lg shadow-lg p-6">
        <h1 className="text-3xl font-bold text-center text-gray-800 mb-6">Web Vulnerability Scanner</h1>
        <Scanner />
      </div>
    </div>
  );
}
