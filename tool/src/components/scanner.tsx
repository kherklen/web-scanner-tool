'use client';
import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import Link from 'next/link';

export default function Scanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  type ScanResults = {
    [key: string]: string;
  } | null;
  const [scanResults, setScanResults] = useState<ScanResults>(null);
  const linkRef = useRef<HTMLAnchorElement>(null); 

  const scanWebsite = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/scan', { url });
      console.log('Raw Response:', response.data);
      const formattedResults = formatResults(response.data);
      console.log('Formatted Results:', formattedResults);
      setScanResults(formattedResults);
      setTimeout(() => {
        linkRef.current?.click();
      }, 0);
    } catch (error) {
      console.error('Error scanning the site:', error);
    }
    setLoading(false);
  };

  const formatResults = (data: { [key in 'sql_injection' | 'xss' | 'csrf' | 'command_injection' | 'open_redirect' | 'directory_traversal' | 'sensitive_data_exposure' | 'stored_xss' | 'api_vulnerabilities']: string }) => {
    const mapping = {
      sql_injection: 'SQL Injection',
      xss: 'Reflected XSS',
      csrf: 'Cross-Site Request Forgery',
      command_injection: 'Command Injection',
      open_redirect: 'Open Redirect',
      directory_traversal: 'Directory Traversal',
      sensitive_data_exposure: 'Sensitive Data Exposure',
      stored_xss: 'Stored XSS',
      api_vulnerabilities: 'API Vulnerabilities',
    };

    return Object.keys(data).reduce((acc, key) => {
      const mappedKey = mapping[key as keyof typeof mapping] || key; 
      acc[mappedKey] = data[key];
      return acc;
    }, {} as { [key: string]: string });
  };

  return (
    <div className="flex flex-col items-center justify-center p-6 space-y-6 text-black">
      <div className="flex items-center space-x-4 w-full">
        <input
          type="text"
          placeholder="Enter website URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="flex-1 p-4 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500"
          style={{ height: '56px' }} 
        />
        <button
          onClick={scanWebsite}
          className="bg-red-600 text-white py-3 px-6 rounded-lg hover:bg-red-700 transition duration-200 ease-in-out"
          style={{ height: '56px' }} 
        >
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>


      {scanResults && (
        <Link
          href={{
            pathname: '/scanResults',
            query: { results: JSON.stringify(scanResults) },
          }}
          ref={linkRef} 
          className="hidden" 
        >
          Go to Results
        </Link>
      )}
    </div>
  );
}
