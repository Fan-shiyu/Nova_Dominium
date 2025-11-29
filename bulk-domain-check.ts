import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.3';
import { PDFDocument, rgb, StandardFonts } from 'https://esm.sh/pdf-lib@1.17.1';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Initialize Supabase client with service role for database operations
const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Backend environment variables
const WHOIS_API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService";
const WHOIS_API_KEY = Deno.env.get('WHOIS_API_KEY');

interface WhoisResult {
  domain_name: string;
  registrant_name: string | null;
  registrant_org: string | null;
  registrar: string | null;
  registry: string | null;
  creation_date: string | null;
  expiry_date: string | null;
  nameservers: string | null;
  data_source: string;
  lookup_timestamp: string;
  risk_flag: "green" | "amber" | "red";
  evidence_file: string;
  risk_types: string;
  lookup_id?: string;
  // Enrichment fields (raw signals for risk logic)
  tls_org?: string | null;
  tls_issuer?: string | null;
  tls_valid_from?: string | null;
  tls_valid_to?: string | null;
  dns_status?: number | null;
  dns_resolves?: boolean;
  dns_nxdomain?: boolean;
  http_status?: number | null;
  http_final_url?: string | null;
  vt_malicious?: boolean;
}

// Expected owner entities for ownership validation
const EXPECTED_OWNERS = [
  "Target Holding B.V.",
  "Target Retail B.V.",
  "Target Group N.V."
];

// Helper function to normalize names for comparison
function normalizeName(s: string | null | undefined): string {
  if (!s) return "";
  return s
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, "") // remove punctuation
    .replace(/\s+/g, " ")
    .trim();
}

// Helper function to fetch RDAP data (free registry-level WHOIS)
async function fetchRdap(domain: string) {
  try {
    console.log(`Fetching RDAP data for: ${domain}`);
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    if (!res.ok) {
      console.warn(`RDAP lookup failed for ${domain}: ${res.status}`);
      return null;
    }
    const data = await res.json();
    
    // Extract useful fields
    const rdapRegistrar = data.entities?.find((e: any) => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] ?? null;
    const rdapEvents = data.events ?? [];
    const rdapNameservers = (data.nameservers ?? []).map((ns: any) => ns.ldhName).filter(Boolean);
    const rdapStatus = data.status ?? [];
    
    // Extract dates from events
    let creationDate: string | null = null;
    let expiryDate: string | null = null;
    
    for (const event of rdapEvents) {
      if (event.eventAction === 'registration') {
        creationDate = event.eventDate;
      } else if (event.eventAction === 'expiration') {
        expiryDate = event.eventDate;
      }
    }
    
    console.log(`RDAP data retrieved for ${domain}: registrar=${rdapRegistrar}, nameservers=${rdapNameservers.length}`);
    
    return {
      rdap_registrar: rdapRegistrar,
      rdap_events: rdapEvents,
      rdap_nameservers: rdapNameservers,
      rdap_status: rdapStatus,
      rdap_creation_date: creationDate,
      rdap_expiry_date: expiryDate,
    };
  } catch (error) {
    console.warn(`Error fetching RDAP for ${domain}:`, error);
    return null;
  }
}

// Helper function to fetch DNS data using Google DNS-over-HTTPS
async function fetchDns(domain: string) {
  try {
    console.log(`Fetching DNS data for: ${domain}`);
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`
    );
    if (!res.ok) {
      console.warn(`DNS lookup failed for ${domain}: ${res.status}`);
      return { error: true };
    }
    const data = await res.json();
    const answers = Array.isArray(data.Answer) ? data.Answer : [];
    
    console.log(`DNS data retrieved for ${domain}: status=${data.Status}, IPs=${answers.length}`);
    
    return {
      dns_status: data.Status,         // 0=OK, 3=NXDOMAIN
      dns_resolves: data.Status === 0,
      dns_nxdomain: data.Status === 3,
      dns_ip_count: answers.length,
    };
  } catch (error) {
    console.warn(`Error fetching DNS for ${domain}:`, error);
    return { error: true };
  }
}

// Helper function to fetch HTTP status and detect redirects
async function fetchHttp(domain: string) {
  try {
    console.log(`Fetching HTTP data for: ${domain}`);
    const res = await fetch(`https://${domain}`, {
      method: "GET",
      redirect: "follow",
    });
    
    console.log(`HTTP data retrieved for ${domain}: status=${res.status}, final_url=${res.url}`);
    
    return {
      http_status: res.status,
      http_final_url: res.url ?? null,
    };
  } catch (error) {
    console.warn(`Error fetching HTTP for ${domain}:`, error);
    return { http_status: null, http_final_url: null };
  }
}

// Helper function to fetch TLS certificate data from crt.sh CT logs
async function fetchTls(domain: string) {
  try {
    console.log(`Fetching TLS certificate data for: ${domain}`);
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
    const res = await fetch(url);
    if (!res.ok) {
      console.warn(`TLS lookup failed for ${domain}: ${res.status}`);
      return null;
    }
    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) {
      console.warn(`No TLS certificates found for ${domain}`);
      return null;
    }
    
    // Get the most recent certificate
    const cert = data[0];
    
    console.log(`TLS data retrieved for ${domain}: CN=${cert.common_name}, org=${cert.name_value}`);
    
    return {
      tls_common_name: cert.common_name ?? null,
      tls_org: cert.name_value ?? null,
      tls_issuer: cert.issuer_name ?? null,
      tls_valid_from: cert.not_before ?? null,
      tls_valid_to: cert.not_after ?? null,
    };
  } catch (error) {
    console.warn(`Error fetching TLS for ${domain}:`, error);
    return null;
  }
}

// Helper function to fetch threat intelligence from VirusTotal (optional)
async function fetchThreat(domain: string) {
  try {
    const vtApiKey = Deno.env.get('VT_API_KEY');
    if (!vtApiKey) {
      console.log(`VT_API_KEY not set, skipping threat intelligence check for ${domain}`);
      return null;
    }
    
    console.log(`Fetching threat intelligence for: ${domain}`);
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { "x-apikey": vtApiKey }
    });
    if (!res.ok) {
      console.warn(`VirusTotal lookup failed for ${domain}: ${res.status}`);
      return null;
    }
    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats ?? {};
    const malicious = (stats.malicious ?? 0) > 0;
    
    console.log(`Threat data retrieved for ${domain}: malicious=${malicious}, stats=${JSON.stringify(stats)}`);
    
    return { vt_malicious: malicious, vt_stats: stats };
  } catch (error) {
    console.warn(`Error fetching threat intelligence for ${domain}:`, error);
    return null;
  }
}

// Helper function to generate PDF evidence
async function generateEvidencePdf(
  result: Omit<WhoisResult, "evidence_file">,
  rawJson: any
): Promise<string> {
  try {
    console.log(`Generating PDF for domain: ${result.domain_name}`);
    
    // Create a new PDF document
    const pdfDoc = await PDFDocument.create();
    let currentPage = pdfDoc.addPage([595.28, 841.89]); // A4 size
    const { width, height } = currentPage.getSize();
    
    // Embed fonts
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
    const monoFont = await pdfDoc.embedFont(StandardFonts.Courier);
    
    let yPosition = height - 50;
    const leftMargin = 50;
    const rightMargin = width - 50;
    const fontSize = 10;
    const headingSize = 14;
    const titleSize = 18;
    const lineHeight = 16;
    
    // Helper to check if we need a new page
    const checkNewPage = (requiredSpace: number = 100) => {
      if (yPosition < requiredSpace) {
        currentPage = pdfDoc.addPage([595.28, 841.89]);
        yPosition = height - 50;
      }
    };
    
    // Helper to draw text with line wrapping
    const drawText = (text: string, x: number, y: number, options: any) => {
      const maxWidth = rightMargin - x;
      const words = text.split(' ');
      let line = '';
      let currentY = y;
      
      for (const word of words) {
        const testLine = line + (line ? ' ' : '') + word;
        const testWidth = options.font.widthOfTextAtSize(testLine, options.size);
        
        if (testWidth > maxWidth && line) {
          currentPage.drawText(line, { ...options, x, y: currentY });
          line = word;
          currentY -= lineHeight;
          checkNewPage();
          yPosition = currentY;
        } else {
          line = testLine;
        }
      }
      
      if (line) {
        currentPage.drawText(line, { ...options, x, y: currentY });
        yPosition = currentY - lineHeight;
      }
    };
    
    // ====================
    // HEADER
    // ====================
    currentPage.drawText('Nova Dominium – Domain Evidence Report', {
      x: leftMargin,
      y: yPosition,
      size: titleSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.5;
    
    const timestamp = new Date().toISOString();
    currentPage.drawText(`Generated by Nova Dominium on ${timestamp}`, {
      x: leftMargin,
      y: yPosition,
      size: fontSize - 1,
      font: font,
      color: rgb(0.4, 0.4, 0.4),
    });
    yPosition -= lineHeight * 2.5;
    
    // ====================
    // SECTION 1: DOMAIN SUMMARY
    // ====================
    checkNewPage(200);
    currentPage.drawText('1. Domain Summary', {
      x: leftMargin,
      y: yPosition,
      size: headingSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.5;
    
    const addField = (label: string, value: string | null | undefined | boolean) => {
      checkNewPage();
      currentPage.drawText(`${label}:`, {
        x: leftMargin + 10,
        y: yPosition,
        size: fontSize,
        font: boldFont,
        color: rgb(0, 0, 0),
      });
      
      const displayValue = value === null || value === undefined ? 'N/A' : String(value);
      currentPage.drawText(displayValue, {
        x: leftMargin + 150,
        y: yPosition,
        size: fontSize,
        font: font,
        color: rgb(0.2, 0.2, 0.2),
      });
      
      yPosition -= lineHeight;
    };
    
    addField('Domain', result.domain_name);
    addField('Overall Risk Flag', result.risk_flag.toUpperCase());
    addField('Risk Types', result.risk_types);
    addField('Created On', result.creation_date);
    addField('Expires On', result.expiry_date);
    addField('Registrar', result.registrar);
    addField('Registry', result.registry);
    addField('Data Source', result.data_source);
    yPosition -= lineHeight;
    
    // ====================
    // SECTION 2: RISK ASSESSMENT
    // ====================
    checkNewPage(200);
    currentPage.drawText('2. Risk Assessment (Nova Dominium)', {
      x: leftMargin,
      y: yPosition,
      size: headingSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.5;
    
    const riskNarrative = `This domain has been assessed with an overall risk flag of ${result.risk_flag.toUpperCase()}. ` +
      `The risk determination is based on multiple factors including domain expiry, ownership verification, ` +
      `and technical consistency across DNS, HTTP, TLS, and threat intelligence signals.`;
    
    drawText(riskNarrative, leftMargin + 10, yPosition, {
      size: fontSize,
      font: font,
      color: rgb(0.2, 0.2, 0.2),
    });
    yPosition -= lineHeight;
    
    checkNewPage(150);
    currentPage.drawText('Risk Type Indicators:', {
      x: leftMargin + 10,
      y: yPosition,
      size: fontSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.2;
    
    const riskTypesList = result.risk_types ? result.risk_types.split(';').map(t => t.trim()) : [];
    for (const riskType of riskTypesList) {
      checkNewPage();
      currentPage.drawText(`• ${riskType}`, {
        x: leftMargin + 20,
        y: yPosition,
        size: fontSize - 1,
        font: font,
        color: rgb(0.3, 0.3, 0.3),
      });
      yPosition -= lineHeight * 0.9;
    }
    yPosition -= lineHeight;
    
    // ====================
    // SECTION 3: WHOIS & RDAP DATA
    // ====================
    checkNewPage(200);
    currentPage.drawText('3. WHOIS & RDAP Data', {
      x: leftMargin,
      y: yPosition,
      size: headingSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.5;
    
    currentPage.drawText('WHOIS Registrant:', {
      x: leftMargin + 10,
      y: yPosition,
      size: fontSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.2;
    
    addField('  Registrant Name', result.registrant_name);
    addField('  Registrant Org', result.registrant_org);
    yPosition -= lineHeight * 0.5;
    
    currentPage.drawText('WHOIS / RDAP Dates and Registrar:', {
      x: leftMargin + 10,
      y: yPosition,
      size: fontSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.2;
    
    addField('  Creation Date', result.creation_date);
    addField('  Expiry Date', result.expiry_date);
    addField('  Registrar', result.registrar);
    yPosition -= lineHeight * 0.5;
    
    currentPage.drawText('Nameservers:', {
      x: leftMargin + 10,
      y: yPosition,
      size: fontSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.2;
    
    const nameserversText = result.nameservers || 'Not available';
    drawText(`  ${nameserversText}`, leftMargin + 10, yPosition, {
      size: fontSize - 1,
      font: font,
      color: rgb(0.3, 0.3, 0.3),
    });
    yPosition -= lineHeight;
    
    if (!result.registrant_name && !result.registrant_org) {
      drawText('Note: WHOIS registrant information is redacted or privacy-protected.', leftMargin + 10, yPosition, {
        size: fontSize - 1,
        font: font,
        color: rgb(0.5, 0, 0),
      });
      yPosition -= lineHeight;
    }
    yPosition -= lineHeight;
    
    // ====================
    // SECTION 4: TECHNICAL SIGNALS
    // ====================
    checkNewPage(250);
    currentPage.drawText('4. Technical Signals (DNS / HTTP / TLS / Threat)', {
      x: leftMargin,
      y: yPosition,
      size: headingSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.5;
    
    // DNS
    currentPage.drawText('DNS Status:', {
      x: leftMargin + 10,
      y: yPosition,
      size: fontSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.2;
    
    let dnsStatus = 'Unknown';
    if (result.dns_nxdomain) {
      dnsStatus = 'NXDOMAIN – domain does not resolve';
    } else if (result.dns_resolves === true) {
      dnsStatus = 'Resolves correctly';
    }
    
    drawText(`  ${dnsStatus}`, leftMargin + 10, yPosition, {
      size: fontSize - 1,
      font: font,
      color: rgb(0.3, 0.3, 0.3),
    });
    yPosition -= lineHeight * 1.5;
    
    // HTTP
    currentPage.drawText('HTTP Status:', {
      x: leftMargin + 10,
      y: yPosition,
      size: fontSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.2;
    
    const httpStatusText = result.http_status !== null && result.http_status !== undefined
      ? `HTTP ${result.http_status}`
      : 'No response';
    drawText(`  ${httpStatusText}`, leftMargin + 10, yPosition, {
      size: fontSize - 1,
      font: font,
      color: rgb(0.3, 0.3, 0.3),
    });
    yPosition -= lineHeight;
    
    if (result.http_final_url) {
      drawText(`  Final URL: ${result.http_final_url}`, leftMargin + 10, yPosition, {
        size: fontSize - 1,
        font: font,
        color: rgb(0.3, 0.3, 0.3),
      });
      yPosition -= lineHeight;
    }
    yPosition -= lineHeight * 0.5;
    
    // TLS
    currentPage.drawText('TLS / Certificate:', {
      x: leftMargin + 10,
      y: yPosition,
      size: fontSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.2;
    
    const tlsOrgText = result.tls_org || 'Not available';
    drawText(`  Certificate Organization: ${tlsOrgText}`, leftMargin + 10, yPosition, {
      size: fontSize - 1,
      font: font,
      color: rgb(0.3, 0.3, 0.3),
    });
    yPosition -= lineHeight;
    
    const tlsValidText = result.tls_valid_to || 'Not available';
    drawText(`  Certificate Valid To: ${tlsValidText}`, leftMargin + 10, yPosition, {
      size: fontSize - 1,
      font: font,
      color: rgb(0.3, 0.3, 0.3),
    });
    yPosition -= lineHeight * 1.5;
    
    // Threat Intelligence
    currentPage.drawText('Threat Intelligence:', {
      x: leftMargin + 10,
      y: yPosition,
      size: fontSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.2;
    
    let vtStatus = 'VirusTotal: Not checked';
    if (result.vt_malicious === true) {
      vtStatus = 'VirusTotal: Malicious indicators present';
    } else if (result.vt_malicious === false) {
      vtStatus = 'VirusTotal: No malicious indicators detected';
    }
    
    drawText(`  ${vtStatus}`, leftMargin + 10, yPosition, {
      size: fontSize - 1,
      font: font,
      color: rgb(0.3, 0.3, 0.3),
    });
    yPosition -= lineHeight * 2;
    
    // ====================
    // SECTION 5: RAW WHOIS / RDAP JSON (APPENDIX)
    // ====================
    checkNewPage(150);
    currentPage.drawText('5. Appendix – Raw WHOIS / RDAP Data', {
      x: leftMargin,
      y: yPosition,
      size: headingSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });
    yPosition -= lineHeight * 1.5;
    
    if (rawJson) {
      const jsonString = JSON.stringify(rawJson, null, 2);
      const maxJsonLength = 3000;
      const truncatedJson = jsonString.length > maxJsonLength
        ? jsonString.substring(0, maxJsonLength) + '\n... (truncated for brevity)'
        : jsonString;
      
      const jsonLines = truncatedJson.split('\n');
      for (const line of jsonLines) {
        checkNewPage(30);
        const truncatedLine = line.substring(0, 90);
        currentPage.drawText(truncatedLine, {
          x: leftMargin + 10,
          y: yPosition,
          size: 7,
          font: monoFont,
          color: rgb(0.3, 0.3, 0.3),
        });
        yPosition -= 10;
      }
    } else {
      drawText('Raw WHOIS / RDAP data not stored for this lookup.', leftMargin + 10, yPosition, {
        size: fontSize - 1,
        font: font,
        color: rgb(0.5, 0.5, 0.5),
      });
    }
    
    // Serialize the PDF to bytes
    const pdfBytes = await pdfDoc.save();
    
    // Upload to Supabase Storage
    const pdfTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `evidence-${result.domain_name}-${pdfTimestamp}.pdf`;
    const filePath = `${fileName}`;
    
    const { data: uploadData, error: uploadError } = await supabase.storage
      .from('evidence-files')
      .upload(filePath, pdfBytes, {
        contentType: 'application/pdf',
        upsert: false,
      });
    
    if (uploadError) {
      console.error(`Error uploading PDF for ${result.domain_name}:`, uploadError);
      throw uploadError;
    }
    
    console.log(`PDF uploaded successfully: ${filePath}`);
    
    // Get public URL
    const { data: urlData } = supabase.storage
      .from('evidence-files')
      .getPublicUrl(filePath);
    
    return urlData.publicUrl;
    
  } catch (error) {
    console.error(`Failed to generate PDF for ${result.domain_name}:`, error);
    throw error;
  }
}

// Helper function to fetch WHOIS info from WhoisXML API
async function fetchWhoisLikeInfo(domain: string): Promise<WhoisResult> {
  console.log(`Fetching WHOIS info for: ${domain}`);
  
  const maxRetries = 2;
  let lastError: Error | null = null;

  // Retry loop for network errors and 5xx responses
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      if (attempt > 0) {
        console.log(`Retry attempt ${attempt} for domain: ${domain}`);
        // Wait before retrying (exponential backoff)
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }

      // Build the API URL
      const url = `${WHOIS_API_URL}?apiKey=${WHOIS_API_KEY}&domainName=${encodeURIComponent(domain)}&outputFormat=json`;
      
      const response = await fetch(url);
      
      // Retry on 5xx errors
      if (response.status >= 500 && attempt < maxRetries) {
        console.warn(`Server error ${response.status} for ${domain}, retrying...`);
        lastError = new Error(`WHOIS API server error: ${response.status}`);
        continue;
      }
      
      if (!response.ok) {
        throw new Error(`WHOIS API error: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      
      // Validate response structure
      if (!data.WhoisRecord) {
        throw new Error('Invalid WHOIS API response: missing WhoisRecord');
      }
      
      const whoisRecord = data.WhoisRecord;
      
      // === STEP 1: Fetch all enrichment signals ===
      console.log(`Running multi-API enrichment for: ${domain}`);
      
      const [rdapData, dnsData, httpData, tlsData, threatData] = await Promise.all([
        fetchRdap(domain),
        fetchDns(domain),
        fetchHttp(domain),
        fetchTls(domain),
        fetchThreat(domain),
      ]);
      
      // === STEP 2: Extract base WHOIS fields ===
      const domainName = whoisRecord.domainName || domain;
      let registrantName = whoisRecord.registrant?.name ?? null;
      let registrantOrg = whoisRecord.registrant?.organization ?? null;
      let registrar = whoisRecord.registrarName ?? null;
      const registry = whoisRecord.registryData?.registrarName ?? null;
      let creationDate = whoisRecord.createdDate ?? whoisRecord.registryData?.createdDate ?? null;
      let expiryDate = whoisRecord.expiresDate ?? whoisRecord.registryData?.expiresDate ?? null;
      
      // Parse nameservers from WHOIS
      let nameservers: string | null = null;
      if (whoisRecord.nameServers?.hostNames && Array.isArray(whoisRecord.nameServers.hostNames)) {
        nameservers = whoisRecord.nameServers.hostNames.join(', ');
      }
      
      // === STEP 3: Merge signals with fallback hierarchy ===
      // Priority: WHOIS > RDAP > TLS
      
      // Fill missing WHOIS fields from RDAP
      if (rdapData) {
        if (!registrar && rdapData.rdap_registrar) {
          registrar = rdapData.rdap_registrar;
          console.log(`Using RDAP registrar for ${domain}: ${registrar}`);
        }
        if (!creationDate && rdapData.rdap_creation_date) {
          creationDate = rdapData.rdap_creation_date;
          console.log(`Using RDAP creation date for ${domain}: ${creationDate}`);
        }
        if (!expiryDate && rdapData.rdap_expiry_date) {
          expiryDate = rdapData.rdap_expiry_date;
          console.log(`Using RDAP expiry date for ${domain}: ${expiryDate}`);
        }
        if (!nameservers && rdapData.rdap_nameservers.length > 0) {
          nameservers = rdapData.rdap_nameservers.join(', ');
          console.log(`Using RDAP nameservers for ${domain}: ${nameservers}`);
        }
      }
      
      // Fill missing registrant_org from TLS certificate org
      if (!registrantOrg && tlsData?.tls_org) {
        registrantOrg = tlsData.tls_org;
        console.log(`Using TLS cert org for ${domain}: ${registrantOrg}`);
      }
      
      // Build comprehensive data source list
      let dataSourceParts = ["WHOIS via WhoisXML API"];
      if (rdapData) dataSourceParts.push("RDAP");
      if (dnsData && !dnsData.error) dataSourceParts.push("DNS");
      if (httpData && httpData.http_status !== null) dataSourceParts.push("HTTP");
      if (tlsData) dataSourceParts.push("TLS");
      if (threatData) dataSourceParts.push("VT");
      const dataSource = dataSourceParts.join(" + ");
      const lookupTimestamp = new Date().toISOString();
      
      console.log(`Merged data for ${domain}: registrar=${registrar}, registrant_org=${registrantOrg}, sources=${dataSource}`);
      
      // Risk calculation logic with structured risk types
      let riskFlag: "green" | "amber" | "red" = "green";
      const riskTypes: string[] = [];
      
      // 1. Calculate expiry risk
      let expiryRisk: "high" | "medium" | "low" | "unknown" = "unknown";
      if (expiryDate) {
        try {
          const exp = new Date(expiryDate);
          const now = new Date();
          const diffDays = (exp.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
          const diffMonths = diffDays / 30;
          
          if (diffMonths < 3) {
            expiryRisk = "high";
          } else if (diffMonths < 12) {
            expiryRisk = "medium";
          } else if (diffMonths >= 12) {
            expiryRisk = "low";
          }
        } catch (e) {
          expiryRisk = "unknown";
        }
      }
      
      riskTypes.push(
        expiryRisk === "high"
          ? "expiry_high"
          : expiryRisk === "medium"
          ? "expiry_medium"
          : expiryRisk === "low"
          ? "expiry_low"
          : "expiry_unknown"
      );
      
      // 2. Ownership signals (WHOIS + TLS)
      const normRegistrantOrg = normalizeName(registrantOrg);
      const normRegistrantName = normalizeName(registrantName);
      const normTlsOrg = normalizeName(tlsData?.tls_org);

      const ownerMatchWhois = EXPECTED_OWNERS.some(o => {
        const n = normalizeName(o);
        return normRegistrantOrg.includes(n) || normRegistrantName.includes(n);
      });

      const ownerMatchTls = EXPECTED_OWNERS.some(o => {
        const n = normalizeName(o);
        return normTlsOrg.includes(n);
      });

      const privacyWords = ["privacy", "redacted", "protected", "whoisguard", "gdpr"];
      const isPrivacy =
        privacyWords.some(w => normRegistrantOrg.includes(w)) ||
        privacyWords.some(w => normRegistrantName.includes(w));

      const owner_unknown =
        (!registrantOrg || normRegistrantOrg === "") || isPrivacy;

      const owner_match = ownerMatchWhois || ownerMatchTls;
      const owner_mismatch =
        !owner_match && !owner_unknown && !!registrantOrg;

      if (owner_match) riskTypes.push(ownerMatchTls ? "ownership_match_tls" : "ownership_match_whois");
      if (owner_unknown) riskTypes.push("ownership_unknown");
      if (owner_mismatch) riskTypes.push("ownership_mismatch");

      if (tlsData?.tls_org) riskTypes.push("tls_org_present");
      if (!tlsData?.tls_org) riskTypes.push("tls_org_missing");
      
      // Check if TLS certificate is expired
      let tlsCertExpired = false;
      if (tlsData?.tls_valid_to) {
        try {
          const validTo = new Date(tlsData.tls_valid_to);
          tlsCertExpired = validTo < new Date();
          if (tlsCertExpired) {
            riskTypes.push("tls_expired");
          }
        } catch (e) {
          console.warn(`Error parsing TLS validity date for ${domain}`);
        }
      }
      
      // 3. DNS signal
      if (dnsData?.dns_nxdomain) {
        riskTypes.push("dns_nxdomain");
      } else if (dnsData?.dns_resolves === true) {
        riskTypes.push("dns_ok");
      } else {
        riskTypes.push("dns_unknown");
      }
      
      // 4. HTTP signal
      if (httpData?.http_status == null) {
        riskTypes.push("http_unreachable");
      } else if (httpData.http_status >= 200 && httpData.http_status < 300) {
        riskTypes.push("http_ok");
      } else if (httpData.http_status >= 300 && httpData.http_status < 400) {
        riskTypes.push("http_redirect");
      } else if (httpData.http_status >= 400) {
        riskTypes.push(`http_${httpData.http_status}`);
      }

      // Optional: if final URL clearly points to expected domains, mark as consistent
      const expectedDomains = ["target.com", "targetgroup.com"]; // placeholder
      if (httpData?.http_final_url) {
        const lowerUrl = httpData.http_final_url.toLowerCase();
        if (expectedDomains.some(d => lowerUrl.includes(d))) {
          riskTypes.push("http_consistent");
        }
      }
      
      // 5. TLS validity
      if (tlsData?.tls_valid_to) {
        const tlsExp = new Date(tlsData.tls_valid_to);
        const now = new Date();
        if (tlsExp.getTime() < now.getTime()) {
          riskTypes.push("tls_expired");
        } else {
          riskTypes.push("tls_valid");
        }
      }
      
      // 6. Threat intelligence
      if (threatData?.vt_malicious === true) {
        riskTypes.push("threat_malicious");
      } else if (threatData?.vt_malicious === false) {
        riskTypes.push("threat_clean");
      }
      
      // 7. Missing critical fields
      const missingCritical =
        !expiryDate || !registrar || registrar === "" || !creationDate;
      if (missingCritical) {
        riskTypes.push("missing_critical_fields");
      }
      
      // 8. Final risk_flag decision (priority)
      // RED conditions (any one makes it red)
      if (
        threatData?.vt_malicious === true ||                     // malicious domain
        owner_mismatch ||                                        // clearly third-party owner
        dnsData?.dns_nxdomain ||                                 // NXDOMAIN
        (expiryRisk === "high" && owner_unknown) ||              // close to expiry + unknown owner
        (httpData?.http_status != null && httpData.http_status >= 400)  // HTTP 4xx/5xx
      ) {
        riskFlag = "red";
      } else {
        // GREEN: clear ownership + good expiry + technically OK
        const technicallyOk =
          dnsData?.dns_resolves === true &&
          httpData?.http_status != null &&
          httpData.http_status >= 200 &&
          httpData.http_status < 400 &&
          !threatData?.vt_malicious &&
          (!tlsData?.tls_valid_to || riskTypes.includes("tls_valid"));

        if (owner_match && expiryRisk === "low" && technicallyOk && !missingCritical) {
          riskFlag = "green";
        } else {
          // everything else is AMBER
          riskFlag = "amber";
        }
      }
      
      console.log(`Risk ${riskFlag.toUpperCase()}: Domain ${domain} - Types: ${riskTypes.join("; ")}`);
      
      // Build the result object with all merged signals (without evidence_file yet)
      const resultData = {
        domain_name: domainName,
        registrant_name: registrantName,
        registrant_org: registrantOrg,
        registrar: registrar,
        registry: registry,
        creation_date: creationDate,
        expiry_date: expiryDate,
        nameservers: nameservers,
        data_source: dataSource,
        lookup_timestamp: lookupTimestamp,
        risk_flag: riskFlag,
        risk_types: riskTypes.join("; "),
        // Attach raw enrichment signals for risk analysis
        tls_org: tlsData?.tls_org ?? null,
        tls_issuer: tlsData?.tls_issuer ?? null,
        tls_valid_from: tlsData?.tls_valid_from ?? null,
        tls_valid_to: tlsData?.tls_valid_to ?? null,
        dns_status: dnsData?.dns_status ?? null,
        dns_resolves: dnsData?.dns_resolves ?? false,
        dns_nxdomain: dnsData?.dns_nxdomain ?? false,
        http_status: httpData?.http_status ?? null,
        http_final_url: httpData?.http_final_url ?? null,
        vt_malicious: threatData?.vt_malicious ?? false,
      };
      
      // Generate PDF evidence
      let evidenceFileUrl = "";
      try {
        evidenceFileUrl = await generateEvidencePdf(resultData, data);
        console.log(`Generated evidence PDF: ${evidenceFileUrl}`);
      } catch (pdfError) {
        console.error(`Failed to generate PDF for ${domain}:`, pdfError);
        evidenceFileUrl = ""; // Set to empty string on error
      }
      
      // Insert raw WHOIS data into database with evidence_file URL
      let lookupId: string | undefined;
      try {
        const { data: insertedRow, error: insertError } = await supabase
          .from('whois_lookups')
          .insert({
            domain: domainName,
            raw_json: data,
            data_source: dataSource,
            lookup_timestamp: lookupTimestamp,
            risk_flag: riskFlag,
            evidence_file: evidenceFileUrl || null,
          })
          .select('id')
          .single();
        
        if (insertError) {
          console.error(`Error inserting WHOIS data for ${domain}:`, insertError);
        } else {
          lookupId = insertedRow.id;
          console.log(`Stored WHOIS lookup with ID: ${lookupId}`);
        }
      } catch (dbError) {
        console.error(`Database error for ${domain}:`, dbError);
      }
      
      return {
        ...resultData,
        evidence_file: evidenceFileUrl,
        lookup_id: lookupId,
      };
      
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      // Only retry on network errors or specific conditions
      const isNetworkError = lastError.message.includes('fetch') || 
                            lastError.message.includes('network') ||
                            lastError.message.includes('timeout');
      
      if (isNetworkError && attempt < maxRetries) {
        console.warn(`Network error for ${domain}, retrying...`);
        continue;
      }
      
      // If we've exhausted retries or it's not a retryable error, break
      break;
    }
  }
  
  // If we get here, all retries failed
  console.error(`Failed to fetch WHOIS for ${domain} after ${maxRetries + 1} attempts:`, lastError?.message);
  
  // Return a red-flagged result on error (no PDF for failed lookups)
  return {
    domain_name: domain,
    registrant_name: null,
    registrant_org: null,
    registrar: null,
    registry: null,
    creation_date: null,
    expiry_date: null,
    nameservers: null,
    data_source: `WHOIS via WhoisXML API (Error: ${lastError?.message})`,
    lookup_timestamp: new Date().toISOString(),
    risk_flag: "red",
    risk_types: "lookup_failed; missing_critical_fields",
    evidence_file: "",
    lookup_id: undefined,
  };
}

// Parse CSV content
function parseCSV(csvContent: string): string[] {
  const lines = csvContent.trim().split('\n');
  
  if (lines.length === 0) {
    throw new Error("CSV file is empty");
  }

  // Parse header
  const header = lines[0].split(',').map(h => h.trim().toLowerCase());
  const domainIndex = header.indexOf('domain_name');

  if (domainIndex === -1) {
    throw new Error("CSV must contain a 'domain_name' column");
  }

  // Parse domains
  const domains: string[] = [];
  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(',').map(v => v.trim());
    const domain = values[domainIndex];
    if (domain && domain.length > 0) {
      domains.push(domain);
    }
  }

  if (domains.length === 0) {
    throw new Error("No valid domains found in CSV");
  }

  return domains;
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Parse multipart form data
    const formData = await req.formData();
    const file = formData.get('file');

    if (!file || !(file instanceof File)) {
      throw new Error("No CSV file provided");
    }

    // Read and parse CSV
    const csvContent = await file.text();
    const domains = parseCSV(csvContent);

    console.log(`Processing ${domains.length} domain(s) from CSV`);

    // Fetch WHOIS info for each domain
    const results = await Promise.all(
      domains.map((domain: string) => fetchWhoisLikeInfo(domain))
    );

    return new Response(
      JSON.stringify({ results }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 200,
      }
    );
  } catch (error) {
    console.error('Error in bulk-domain-check function:', error);
    const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
    return new Response(
      JSON.stringify({ error: errorMessage }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 400,
      }
    );
  }
});
