require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
app.use(express.json());

// ✅ Static CORS config for GitHub Pages
app.use(cors({
  origin: 'https://shreyansh-123.github.io',
  methods: ['GET'],
  optionsSuccessStatus: 200,
  allowedHeaders: ['Content-Type']
}));

// Serve frontend (optional for local use)
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Utility functions
async function fetchJSON(url, headers = {}) {
  const res = await fetch(url, { headers });
  return res.json();
}
function isValidIP(ioc) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ioc);
}
function isValidURL(ioc) {
  try {
    new URL(ioc);
    return true;
  } catch {
    return false;
  }
}

// Threat Intel handlers
const lookupHandlers = {
  virustotal: async (ioc, keys) => {
    const key = keys.vt || process.env.VT_API_KEY;
    const url = `https://www.virustotal.com/api/v3/search?query=${ioc}`;
    const json = await fetchJSON(url, { 'x-apikey': key });
    const data = json.data?.[0]?.attributes || {};
    const stats = data.last_analysis_stats || {};
    const vendorsFlagged = Object.values(data.last_analysis_results || {}).filter(r => r.category === 'malicious').length;

    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      vendorsFlagged,
      country: data.country || 'N/A',
      isp: data.as_owner || 'N/A'
    };
  },

  abuseipdb: async (ioc, keys) => {
    if (!isValidIP(ioc)) throw new Error('AbuseIPDB supports only IPs');
    const key = keys.abuse || process.env.ABUSE_API_KEY;
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90&verbose`;
    const json = await fetchJSON(url, {
      'Key': key,
      'Accept': 'application/json'
    });
    const d = json.data || {};
    return {
      abuseConfidenceScore: d.abuseConfidenceScore,
      totalReports: d.totalReports,
      isp: d.isp,
      usageType: d.usageType,
      domain: d.domain,
      country: d.countryName,
      city: d.city,
      asn: d.asn
    };
  },

  shodan: async (ioc, keys) => {
    if (!isValidIP(ioc)) throw new Error('Shodan supports only IPs');
    const key = keys.shodan || process.env.SHODAN_API_KEY;
    const url = `https://api.shodan.io/shodan/host/${ioc}?key=${key}`;
    const json = await fetchJSON(url);
    return {
      ports: json.ports || [],
      city: json.city,
      country_name: json.country_name,
      org: json.org,
      hostnames: json.hostnames
    };
  },

  ipapi: async (ioc) => {
    if (!isValidIP(ioc)) throw new Error('ipapi supports only IPs');
    const json = await fetchJSON(`http://ip-api.com/json/${ioc}`);
    return {
      country: json.country,
      region: json.regionName,
      isp: json.isp
    };
  },

  ipqualityscore: async (ioc, keys) => {
    if (!isValidIP(ioc)) throw new Error('IPQualityScore supports only IPs');
    const key = keys.ipqs || process.env.IPQS_API_KEY;
    const url = `https://ipqualityscore.com/api/json/ip/${key}/${ioc}`;
    const json = await fetchJSON(url);
    return {
      fraudScore: json.fraud_score,
      isProxy: json.proxy,
      isVPN: json.vpn,
      recentAbuse: json.recent_abuse,
      country: json.country_code,
      isp: json.ISP,
      usageType: json.usage_type,
      asn: json.ASN
    };
  },

  urlscan: async (ioc) => {
    if (!isValidURL(ioc)) throw new Error('Urlscan supports only URLs');
    const url = `https://urlscan.io/api/v1/search/?q=domain:${new URL(ioc).hostname}`;
    const json = await fetchJSON(url);
    const result = json.results?.[0] || {};
    return {
      task: result.task || {},
      verdicts: result.verdicts || {},
      page: result.page || {}
    };
  }
};

// ✅ GET-based lookup route
app.get('/lookup', async (req, res) => {
  const queryParam = req.query.query || '';
  const iocs = queryParam.split(',').map(i => i.trim()).filter(i => i);

  const keys = {
    vt: req.query.vt,
    abuse: req.query.abuse,
    shodan: req.query.shodan,
    ipqs: req.query.ipqs
  };

  const results = [];

  for (const ioc of iocs) {
    const result = { ioc, details: {}, summary: [] };
    const type = isValidIP(ioc) ? 'ip' : isValidURL(ioc) ? 'url' : 'hash';

    for (const [source, handler] of Object.entries(lookupHandlers)) {
      try {
        if (['abuseipdb', 'shodan', 'ipapi', 'ipqualityscore'].includes(source) && type !== 'ip') continue;
        if (source === 'urlscan' && type !== 'url') continue;

        const data = await handler(ioc, keys);
        result.details[source] = data;

        if (source === 'virustotal') {
          const isMalicious = data.malicious > 0;
          const isSuspicious = data.suspicious > 0;
          let vtSummary = `[VirusTotal] involved ${ioc} is found ${isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : 'clean'}`;
          if (isMalicious) vtSummary += ` by ${data.vendorsFlagged} vendors`;
          vtSummary += ` on VT`;
          if (type === 'ip') vtSummary += ` and ISP is ${data.isp} and belongs to country ${data.country}`;
          result.summary.push(vtSummary);
        }

        if (source === 'abuseipdb') {
          result.summary.push(`[AbuseIPDB] ${ioc} has ${data.totalReports} reports with ${data.abuseConfidenceScore}% confidence of abuse. ISP is ${data.isp}, usage: ${data.usageType}, country: ${data.country}`);
        }

        if (source === 'shodan') {
          result.summary.push(`[Shodan] ${ioc} open ports: ${data.ports.join(', ') || 'None'}, Host: ${data.org}, Location: ${data.city}, ${data.country_name}`);
        }

        if (source === 'ipqualityscore') {
          result.summary.push(`[IPQualityScore] ${ioc} fraud score: ${data.fraudScore}, proxy: ${data.isProxy}, ISP: ${data.isp}, Country: ${data.country}`);
        }

        if (source === 'urlscan') {
          const tags = data.page?.tags?.join(', ') || 'N/A';
          const registrar = data.page?.registrar || 'N/A';
          result.summary.push(`[Urlscan] ${ioc} scanned. Tags: ${tags}, Registrar: ${registrar}, Verdict: ${data.verdicts?.overall?.score || 'N/A'}, Last scan: ${data.task?.time || 'N/A'}`);
        }

      } catch (err) {
        result.details[source] = { error: err.message };
      }
    }

    results.push(result);
  }

  res.json({ results });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ TI backend running on port ${PORT}`);
});
