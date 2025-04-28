'use client';

import { useSearchParams } from 'next/navigation';
import { useState } from 'react';
import Scanner from '../../components/scanner';
export default function ScanResults() {
  const searchParams = useSearchParams();
  const results = searchParams.get('results');
  const required_headers = [
    {
      name: 'Strict-Transport-Security',
      description: 'HTTP Strict Transport Security нь таны сайтад хэрэглэхэд маш сайн боломж бөгөөд TLS-г хэрэгжүүлэхэд тань тусалж, хэрэглэгчийн агентын (User Agent) HTTPS ашиглахыг албадан хэрэгжүүлдэг.'
    },
    {
      name: 'Content-Security-Policy',
      description: 'Контентийн Аюулгүй Байдлын Бодлого нь XSS халдлагуудаас таны сайтыг хамгаалахад үр дүнтэй арга юм. Зөвшөөрөгдсөн контентын эх сурвалжуудыг цагаан жагсаалтад оруулснаар та браузерт муу санаатай ачааллуудыг оруулахыг хориглоно.'
    },
    {
      name: 'X-Frame-Options',
      description: 'X-Frame-Options нь таны сайтаа фрейм хийхийг зөвшөөрөх эсэхийг хөтчид хэлдэг. Сайтаа фрейм хийхийг хориглох нь clickjacking гэх мэт халдлагуудаас хамгаалах хэрэгтэй. Зөвлөмж болгож буй утга: "X-Frame-Options: SAMEORIGIN".'
    },
    {
      name: 'X-Content-Type-Options',
      description: 'X-Content-Type-Options нь браузерт контентийн төрлийг MIME-снфф хийхийг хориглож, тодорхойлсон контентийн төрлийг мөрдөхийг албадан шаарддаг. Энэ хаягийн зөвхөн зөв утга нь "X-Content-Type-Options: nosniff".'
    },
    {
      name: 'Referrer-Policy',
      description: 'Referrer Policy нь сайтынхаа хуудаснаас өөр хуудас руу шилжихэд браузерт ямар мэдээллийг дамжуулахыг хянах боломжийг олгодог шинэ хаяг юм. Энэ хаягийг бүх сайтууд тохируулах ёстой.'
    },
    {
      name: 'Permissions-Policy',
      description: 'Permissions Policy нь сайтуудад браузер дээрх ямар функцууд болон API-уудыг ашиглах боломжтойг хянах боломжийг олгодог шинэ хаяг юм.'
    }
  ];

  const scanResults = results ? JSON.parse(results) : {};

  const potentialRisks = {
    'Reflected XSS': 'Хэрэглэгчийн оруулсан өгөгдлийг баталгаажуулахгүй орчинд ажиллуулснаар скрипт гүйцэтгэхэд хүргэдэг халдлага. Шийдэл: Оролтод шүүлт хийх, гаралтод шүүлт хийх (input validation, output encoding), мөн Content Security Policy (CSP)-г ашиглах.',
    'Stored XSS': 'Сервер дээр хадгалагдсан скрипт хэрэглэгчдэд автоматаар илгээгдэж, халдлагын суурь болдог. Шийдэл: Оролтод шүүлт хийх, гаралтод шүүлт хийх, мөн хэрэглэгчдийн оруулсан өгөгдлийг баталгаажуулах.',
    'Command Injection': 'Системийн командуудыг хууль бусаар гүйцэтгүүлэх замаар серверийн нэвтрэх эрхийг зөрчих халдлага. Шийдэл: Оролтын өгөгдлийг тохирох хязгаарлалттай болгож, параметртэй командын хэрэглээг зөвшөөрөх.',
    'Open Redirect': 'Хэрэглэгчийг хуурамч вэбсайт руу дахин чиглүүлэх замаар мэдээллийг хулгайлах эрсдэл үүсгэдэг. Шийдэл: URL-ийг баталгаажуулах, мөн зөвхөн итгэмжлэгдсэн домэйнууд руу дахин чиглүүлэхийг зөвшөөрөх.',
    'Directory Traversal': 'Файлын замыг зүй бусаар ашиглан серверийн файлд хандахыг оролдох халдлага. Шийдэл: Файлын замыг баталгаажуулах, зөвхөн хүлээн зөвшөөрөгдсөн замуудыг нээх.',
    'Sensitive Data Exposure': 'Мэдрэмтгий өгөгдөл шифрлэлгүй дамжуулах эсвэл хууль бусаар ил болгох эрсдэл. Шийдэл: HTTPS ашиглах, өгөгдлийг шифрлэх, мөн зөвшөөрөлгүй хандалтаас хамгаалах.',
    'Clickjacking': 'Хэрэглэгчийн санаандгүйгээр хортой товшилт хийхэд хүргэдэг довтолгоо. Шийдэл: X-Frame-Options толгойг "DENY" эсвэл "SAMEORIGIN"-д тохируулах.',
    'CSRF': 'Хэрэглэгчийн хуурамч хүсэлтийг хүлээн авч, зөвшөөрөлгүй үйлдэл хийх халдлага. Шийдэл: CSRF токен ашиглах, мөн Origin болон Referer толгойг шалгах.',
  };


  const [expandedVulnerabilities, setExpandedVulnerabilities] = useState<{ [key: string]: boolean }>({});

  const toggleVulnerability = (key) => {
    setExpandedVulnerabilities((prevState) => ({
      ...prevState,
      [key]: !prevState[key],
    }));
  };

  const vulnerabilityKeys = Object.keys(scanResults).filter(
    (key) =>
      key !== 'IP address' &&
      key !== 'Domain' &&
      key !== 'HTTP Headers' &&
      key !== 'Missing Headers' &&
      key !== 'URL'
  );
  const totalVulnerabilities = vulnerabilityKeys.length;
  const failCount = vulnerabilityKeys.filter(
    (key) => scanResults[key]?.toLowerCase().includes('fail')
  ).length;
  const passCount = vulnerabilityKeys.filter(
    (key) => scanResults[key]?.toLowerCase().includes('pass')
  ).length;

  // Determine background color
  const summaryBgClass =
    failCount / totalVulnerabilities >= 0.5
      ? 'bg-red-500 border-red-200'
      : failCount / totalVulnerabilities > 0.4
        ? 'bg-yellow-500 border-yellow-200'
        : 'bg-green-500 border-green-200';

  return (
    <body className='bg-white'>
      <div className={`w-full h-1/3 ${summaryBgClass} flex flex-col items-center justify-center py-10`}>
        <h1 className="text-3xl font-bold text-center text-gray-800">Web Vulnerability Scanner</h1>
        <Scanner />
      </div>

      <div className="min-h-screen bg-white text-black w-2/3  mx-auto flex items-center justify-center mt-10 mb-10">

        <div className="p-6 space-y-6 max-w-[800px] w-full">
          {/* Summary Section */}
          <h2 className="text-xl font-semibold mb-2">Basic information</h2>
          <div className={`p-4 border rounded-lg`}>
            <p>
              <strong>Site:</strong> {scanResults["URL"]}
            </p>
            <p>
              <strong>IP Address:</strong> {scanResults['IP address']}
            </p>
            <p>
              <strong>Domain:</strong> {scanResults['Domain']}
            </p>
          </div>

          {/* HTTP Headers Section */}
          <h2 className="text-xl font-semibold mb-2">Missing Headers</h2>
          {required_headers.some((header) => !scanResults['HTTP Headers']?.includes(header.name)) && (
            <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">

             
              <div className="space-y-4 mt-2">
                {required_headers.map((header, index) => {
                  
                  const isMissing = scanResults['HTTP Headers']?.includes(header.name);

                  return (
                    isMissing && (
                      <div
                        key={`${header.name}-${index}`}
                        className="flex items-start w-full"
                      >
                        
                        <div className="w-1/3 text-sm font-medium text-gray-900">
                          {header.name}
                        </div>

                       
                        <div className="w-2/3 text-sm text-gray-700">
                          {header.description}
                        </div>
                      </div>
                    )
                  );
                })}
              </div>
            </div>
          )}










          {/* Vulnerabilities Section */}
          <h2 className="text-xl font-semibold mb-2">Vulnerabilities</h2>
          <div className="space-y-4">
            {vulnerabilityKeys.map((key) => {
              const isPass = scanResults[key]?.toLowerCase().includes('pass');
              return (
                <div
                  key={key}
                  className={`w-full max-w-[800px] p-4 border rounded-lg overflow-hidden ${isPass ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                    }`}
                >
                  <h3 className="text-lg font-medium">{key}</h3>
                  <p
                    className={`text-sm font-semibold ${isPass ? 'text-green-600' : 'text-red-600'
                      }`}
                  >
                    {scanResults[key]}
                  </p>
                  {!isPass && (
                    <>
                      <button
                        className="text-blue-600 underline text-sm mt-2"
                        onClick={() => toggleVulnerability(key)}
                      >
                        {expandedVulnerabilities[key] ? 'Show Less' : 'Show More'}
                      </button>
                      {expandedVulnerabilities[key] && (
                        <p className="mt-2 text-sm">
                          {potentialRisks[key] || 'No description available.'}
                        </p>
                      )}
                    </>
                  )}
                </div>
              );
            })}
          </div>
        </div>



      </div>
    </body>
  );
}
