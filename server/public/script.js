async function lookupIOCs() {
  const input = document.getElementById('iocInput').value.trim();
  if (!input) return alert('Please enter some IOCs.');

  const iocs = input.split('\n').map(i => i.trim()).filter(i => i);
  const vt = document.getElementById('vtKey').value.trim();
  const abuse = document.getElementById('abuseKey').value.trim();
  const shodan = document.getElementById('shodanKey').value.trim();
  const ipqs = document.getElementById('ipqsKey').value.trim();

  const query = iocs.join(',');
  const url = `https://threat-intel-tmjz.onrender.com/lookup?query=${encodeURIComponent(query)}&vt=${vt}&abuse=${abuse}&shodan=${shodan}&ipqs=${ipqs}`;

  const resultsDiv = document.getElementById('results');
  const summaryDiv = document.getElementById('summary');

  resultsDiv.innerHTML = '';
  summaryDiv.innerHTML = '<b>Final Summary:</b><br><br>';

  try {
    const response = await fetch(url);
    const { results } = await response.json();

    results.forEach(result => {
      const box = document.createElement('div');
      box.className = 'result-box';

      let html = `🔎 <b>${result.ioc}</b><br>`;
      for (const [source, data] of Object.entries(result.details)) {
        html += `<br>${getIcon(source)} <b>${source.toUpperCase()}</b><pre>${JSON.stringify(data, null, 2)}</pre>`;
      }
      box.innerHTML = html;
      resultsDiv.appendChild(box);

      result.summary.forEach(line => {
        const span = document.createElement('div');
        const isMalicious = /malicious|suspicious|fraud score of [6-9]\d|confidence of abuse|proxy: true|recent_abuse: true/i.test(line);
        span.className = isMalicious ? 'malicious' : 'clean';
        span.textContent = line;
        summaryDiv.appendChild(span);
      });
    });
  } catch (err) {
    resultsDiv.innerHTML = `<div class="malicious">❌ Error: ${err.message}</div>`;
  }
}

function getIcon(source) {
  const icons = {
    virustotal: '🛡',
    abuseipdb: '🗡',
    shodan: '🌐',
    ipapi: '📍',
    ipqualityscore: '🧠',
    urlscan: '🔍'
  };
  return icons[source] || '📁';
}
