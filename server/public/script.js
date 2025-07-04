async function lookupIOCs() {
  const input = document.getElementById('iocInput').value.trim();
  if (!input) return alert('Please enter some IOCs.');

  const iocs = input.split('\n').map(i => i.trim()).filter(i => i);
 const response = await fetch('https://threat-intel-tmjz.onrender.com/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({
  iocs,
  keys: {
    vt: document.getElementById('vtKey').value.trim(),
    abuse: document.getElementById('abuseKey').value.trim(),
    shodan: document.getElementById('shodanKey').value.trim(),
    ipqs: document.getElementById('ipqsKey').value.trim()
  }
})

  });

  const { results } = await response.json();
  const resultsDiv = document.getElementById('results');
  const summaryDiv = document.getElementById('summary');

  resultsDiv.innerHTML = '';
  summaryDiv.innerHTML = '<b>Final Summary:</b><br><br>';

  results.forEach(result => {
    const box = document.createElement('div');
    box.className = 'result-box';

    let html = `🔎 <b>${result.ioc}</b><br>`;
    for (const [source, data] of Object.entries(result.details)) {
      html += `<br>${getIcon(source)} <b>${source.toUpperCase()}</b><pre>${JSON.stringify(data, null, 2)}</pre>`;
    }
    box.innerHTML = html;
    resultsDiv.appendChild(box);

    // Determine if any tool marked IOC as malicious
    const isMalicious = result.summary.some(line =>
      /malicious|fraud score of [6-9]\d|confidence of abuse|proxy: true|recent_abuse: true/i.test(line)
    );

    result.summary.forEach(line => {
  const span = document.createElement('div');

  const isMalicious = /malicious|suspicious|fraud|abuse/i.test(line);
  span.className = isMalicious ? 'malicious' : 'clean';
  
  span.textContent = line;
  summaryDiv.appendChild(span);
});

  });
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
