/*
 * GitHub Pages / static-site data adapter.
 * Reads only the repository's bundled CSV/JSON files. User edits stay in this browser's localStorage.
 * No fetch is made to an IOC, domain, IP, CVE service, or external API.
 */
(() => {
  'use strict';
  const PREFIX = 'signal-atlas-static-';
  const base = document.documentElement.dataset.base || './';
  const dataUrl = (name) => new URL(`${base}data/${name}`, window.location.href).toString();
  let dataPromise;

  function parseCSV(text) {
    const source = String(text || '').replace(/^\uFEFF/, '');
    const rows = []; let row = []; let field = ''; let quoted = false;
    for (let i = 0; i < source.length; i++) {
      const ch = source[i];
      if (quoted) {
        if (ch === '"' && source[i + 1] === '"') { field += '"'; i++; }
        else if (ch === '"') quoted = false;
        else field += ch;
      } else if (ch === '"') quoted = true;
      else if (ch === ',') { row.push(field); field = ''; }
      else if (ch === '\n') { row.push(field.replace(/\r$/, '')); rows.push(row); row = []; field = ''; }
      else field += ch;
    }
    if (field.length || row.length) { row.push(field.replace(/\r$/, '')); rows.push(row); }
    if (!rows.length) return [];
    const headers = rows.shift().map((x) => x.trim());
    return rows.filter((r) => r.some((x) => x !== '')).map((values) => Object.fromEntries(headers.map((key, i) => [key, values[i] ?? ''])));
  }

  async function getText(name) {
    const response = await fetch(dataUrl(name), { cache: 'force-cache', credentials: 'same-origin' });
    if (!response.ok) throw new Error(`Could not load bundled ${name} (${response.status}). Rebuild the GitHub Pages folder and publish /docs.`);
    return response.text();
  }
  async function getJSON(name) { return JSON.parse(await getText(name)); }
  async function loadData() {
    const [threatText, vulnerabilityText, modules, quiz, assets, signals, awarenessMetrics] = await Promise.all([
      getText('threat_intelligence_dataset.csv'), getText('vulnerabilities.csv'),
      getJSON('modules.json'), getJSON('quiz_questions.json'), getJSON('assets.json'),
      getText('internal_signals.csv').then(parseCSV), getJSON('awareness_metrics.json'),
    ]);
    const threats = parseCSV(threatText).map((row) => ({
      ...row,
      risk_score: Number(row.risk_score || 0),
      confidence_score: Number(row.confidence_score || 0),
      observed_count: Number(row.observed_count || 1),
    }));
    const vulnerabilities = parseCSV(vulnerabilityText).map((row) => ({
      ...row, cvss_score: Number(row.cvss_score || 0),
      asset_criticality: Number(row.asset_criticality || 0),
      exposure_score: Number(row.exposure_score || 0),
      business_context: Number(row.business_context || 0),
      patch_available: String(row.patch_available).toUpperCase() === 'YES',
    }));
    return { threats, vulnerabilities, modules, quiz, assets, signals, awarenessMetrics };
  }
  function getData() { if (!dataPromise) dataPromise = loadData(); return dataPromise; }

  function readStore(key, fallback = null) {
    try { const raw = localStorage.getItem(PREFIX + key); return raw === null ? fallback : JSON.parse(raw); }
    catch { return fallback; }
  }
  function writeStore(key, value) {
    try { localStorage.setItem(PREFIX + key, JSON.stringify(value)); }
    catch { throw new Error('Browser storage is unavailable or full. Export important notes before clearing site data.'); }
  }
  const number = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;
  const clamp = (value) => Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
  const riskBand = (score) => score <= 20 ? 'INFORMATIONAL' : score <= 40 ? 'LOW' : score <= 60 ? 'MEDIUM' : score <= 80 ? 'HIGH' : 'CRITICAL';
  const cvssBand = (score) => score === 0 ? 'INFORMATIONAL' : score < 4 ? 'LOW' : score < 7 ? 'MEDIUM' : score < 9 ? 'HIGH' : 'CRITICAL';

  function calculateVulnerabilityPriority(item) {
    const cvss = Math.max(0, Math.min(10, number(item.cvss_score))) * 10;
    const exploitation = String(item.exploitation_status_demo).toUpperCase() === 'YES' ? 100 : 20;
    return clamp(cvss * .30 + number(item.asset_criticality) * .25 + number(item.exposure_score) * .15 + exploitation * .20 + number(item.business_context) * .10);
  }
  function getVulnerabilities(data, params) {
    return data.vulnerabilities.map((item) => {
      const priority = calculateVulnerabilityPriority(item);
      const exposure = item.exposure_score >= 70 ? 'internet-facing' : 'restricted/limited exposure';
      const criticality = item.asset_criticality >= 70 ? 'high-criticality' : 'standard-criticality';
      const evidence = String(item.exploitation_status_demo).toUpperCase() === 'YES' ? 'demo exploitation evidence is marked' : 'no demo exploitation evidence is marked';
      return { ...item, severity: cvssBand(item.cvss_score), priority_score: priority, is_synthetic: true,
        priority_explanation: `Priority considers CVSS, ${criticality} asset context, ${exposure}, and whether ${evidence}; it is not a live vulnerability verdict.` };
    }).filter((item) => item.priority_score >= number(params.get('min_priority')) && (!params.get('severity') || item.severity === params.get('severity').toUpperCase()))
      .sort((a,b) => b.priority_score-a.priority_score || b.cvss_score-a.cvss_score);
  }

  function getAllThreats(data) {
    const additions = readStore('threats', []);
    const statusOverrides = readStore('threat-statuses', {});
    return [...data.threats, ...additions].map((item) => ({
      ...item, status: statusOverrides[item.threat_id] || item.status,
      risk_score: number(item.risk_score), confidence_score: number(item.confidence_score), observed_count: number(item.observed_count,1),
    }));
  }
  function getNotes() {
    const notes = readStore('notes', null);
    if (notes) return notes;
    const seed = { 'THR-2026-001': [{ note_id: 'NOTE-DEMO-001', threat_id: 'THR-2026-001', note: 'Indicator appears in multiple synthetic phishing observations. Review authorized local telemetry; no external domain was visited.', created_at: '2026-09-18T09:00:00Z', author_label: 'DEMO ANALYST' }] };
    writeStore('notes', seed); return seed;
  }
  function getThreatDetail(threat, all, alerts) {
    const campaign = threat.campaign_id;
    const related = campaign ? all.filter((x) => x.campaign_id === campaign && x.threat_id !== threat.threat_id).map((x) => ({
      threat_id:x.threat_id, indicator_type:x.indicator_type, indicator_value:x.indicator_value,
      threat_category:x.threat_category, severity:x.severity, risk_score:x.risk_score, status:x.status,
    })) : [];
    const mappings = threat.mitre_tactic_optional ? [{ tactic:threat.mitre_tactic_optional, technique:threat.mitre_technique_optional || null, technique_id_optional:threat.mitre_technique_id_optional || null }] : [];
    return { ...threat, related_indicators:related,
      related_alerts:alerts.filter((x) => x.threat_id === threat.threat_id),
      analyst_notes:(getNotes()[threat.threat_id] || []), attack_mappings:mappings,
      timeline:[
        { time:threat.first_seen, label:'First observed', detail:'Synthetic dataset timestamp.' },
        { time:threat.timestamp, label:'Latest observation', detail:`${threat.observed_count} synthetic observation(s).` },
        { time:threat.last_seen, label:'Last seen', detail:`Current state: ${threat.status} (not a confirmed incident).` },
      ] };
  }

  function validateIndicator(value) {
    const raw = String(value || '').trim();
    const invalid = (kind, notes) => ({ valid:false, indicator_type:kind, normalized_value:raw, validation_notes:notes });
    if (!raw) return invalid('DOMAIN','A value is required. No network lookup was performed.');
    const cve = /^CVE-\d{4}-\d{4,}$/i;
    if (cve.test(raw)) return { valid:true, indicator_type:'CVE ID', normalized_value:raw.toUpperCase(), validation_notes:'CVE identifier syntax is valid; existence and vulnerability status were not checked.' };
    if (/^[a-f0-9]{32}$/i.test(raw) || /^[a-f0-9]{40}$/i.test(raw) || /^[a-f0-9]{64}$/i.test(raw)) return { valid:true, indicator_type:'FILE HASH', normalized_value:raw.toLowerCase(), validation_notes:'Hash format is syntactically valid; no file was opened or executed.' };
    const v4 = raw.split('.');
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw)) {
      const valid = v4.every((part) => Number(part) >= 0 && Number(part) <= 255);
      return valid ? { valid:true, indicator_type:'IP ADDRESS', normalized_value:v4.map(Number).join('.'), validation_notes:'Syntactically valid IPv4; no connection was attempted.' } : invalid('IP ADDRESS','Not a valid IPv4 address. No network lookup was performed.');
    }
    if (raw.includes(':') && !raw.includes('/')) {
      try { const parsed = new URL(`http://[${raw}]/`); if (parsed.hostname) return { valid:true, indicator_type:'IP ADDRESS', normalized_value:parsed.hostname.slice(1,-1).toLowerCase(), validation_notes:'Syntactically valid IPv6; no connection was attempted.' }; }
      catch { /* continue with other parsers */ }
    }
    function domainOK(host) {
      const name = String(host || '').toLowerCase().replace(/\.$/,'');
      if (name.length > 253 || !name.includes('.')) return false;
      const labels = name.split('.');
      return labels.every((part) => part.length > 0 && part.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(part)) && labels.at(-1).length >= 2 && !/^\d+$/.test(labels.at(-1));
    }
    if (raw.includes('@')) {
      const [local, host] = [raw.slice(0,raw.lastIndexOf('@')), raw.slice(raw.lastIndexOf('@')+1)];
      const valid = Boolean(local) && local.length <= 64 && !/\s/.test(local) && domainOK(host);
      return valid ? { valid:true, indicator_type:'EMAIL/SENDER DOMAIN', normalized_value:`${local.toLowerCase()}@${host.toLowerCase().replace(/\.$/,'')}`, validation_notes:'Syntactically valid sender/domain value; mailbox ownership was not checked.' } : invalid('EMAIL/SENDER DOMAIN','Invalid sender/domain syntax. No lookup was performed.');
    }
    if (/^https?:\/\//i.test(raw)) {
      try {
        const url = new URL(raw); const valid = ['http:','https:'].includes(url.protocol) && Boolean(url.hostname) && !url.username && !url.password && (url.hostname.startsWith('[') || domainOK(url.hostname));
        if (valid) return { valid:true, indicator_type:'URL', normalized_value:url.toString(), validation_notes:'URL syntax is valid; it was not opened or contacted.' };
      } catch { /* invalid URL */ }
      return invalid('URL','Invalid or unsupported URL syntax; the value was not contacted.');
    }
    const domain = raw.toLowerCase().replace(/\.$/,'');
    return domainOK(domain) ? { valid:true, indicator_type:'DOMAIN', normalized_value:domain, validation_notes:'Syntactically valid domain; reputation and ownership were not checked.' } : invalid('DOMAIN','Invalid domain syntax. No DNS lookup was performed.');
  }

  function getAlerts(data, all) {
    let alerts = readStore('alerts', null);
    if (!alerts) {
      const eligible = [...all].filter((x) => x.risk_score >= 61 && x.confidence_score >= 35).sort((a,b) => b.risk_score-a.risk_score || b.confidence_score-a.confidence_score);
      const demo = all.find((x) => x.threat_id === 'THR-2026-001');
      const chosen = demo ? [demo, ...eligible.filter((x) => x.threat_id !== demo.threat_id)] : eligible;
      alerts = [];
      for (const threat of chosen.slice(0,36)) {
        const reasons=[];
        if (threat.risk_score>=61 && threat.confidence_score>=35) reasons.push('risk and confidence thresholds met');
        if (threat.observed_count>=5) reasons.push('repeated observations');
        const relatedCount=threat.campaign_id?2:0;
        if (relatedCount>=2) reasons.push('correlated indicators present');
        if (!reasons.length) continue;
        alerts.push({ alert_id:`ALT-DEMO-${String(alerts.length+1).padStart(4,'0')}`, threat_id:threat.threat_id,
          timestamp:threat.timestamp, alert_type:relatedCount>=2?'CORRELATED_INDICATOR':'THREAT_REVIEW', severity:threat.severity,
          risk_score:threat.risk_score, confidence_score:threat.confidence_score,
          description:`Analyst review recommended: ${reasons.join(', ')}. This alert is not a confirmed incident.`,
          status:'NEW', indicator_value:threat.indicator_value, observation_count:threat.observed_count, dedupe_key:`${threat.indicator_type}:${threat.indicator_value}:${threat.threat_category}`.toLowerCase() });
      }
      for (const item of getVulnerabilities(data,new URLSearchParams())) {
        const flagged=String(item.exploitation_status_demo).toUpperCase()==='YES';
        if (!(item.priority_score>=80 || (item.priority_score>=65 && flagged))) continue;
        alerts.push({ alert_id:`ALT-CVE-${item.cve_id}`, threat_id:null, timestamp:`${item.published_date}T00:00:00Z`, alert_type:'HIGH_PRIORITY_VULNERABILITY',
          severity:riskBand(item.priority_score), risk_score:item.priority_score, confidence_score:70,
          description:`Fictional CVE scenario ${item.cve_id} reached the local priority threshold. No real advisory or exploitation is represented.`,
          status:'NEW', indicator_value:item.cve_id, observation_count:1, dedupe_key:`vulnerability:${item.cve_id}`.toLowerCase() });
      }
      writeStore('alerts', alerts);
    }
    return alerts.map((item) => ({...item}));
  }

  function categoryStats(rows, key) {
    const counts={}; rows.forEach((row)=>{const name=row[key]||'UNKNOWN';counts[name]=(counts[name]||0)+1;}); return counts;
  }
  function getStats(rows, vulnerabilities) {
    const severity=categoryStats(rows,'severity'), categories=categoryStats(rows,'threat_category'), types=categoryStats(rows,'indicator_type'), statuses=categoryStats(rows,'status');
    const bins=['0–20','21–40','41–60','61–80','81–100']; const riskBins=Object.fromEntries(bins.map((x)=>[x,0])); const confidenceBins=Object.fromEntries(bins.map((x)=>[x,0]));
    const bin=(n)=>n<=20?bins[0]:n<=40?bins[1]:n<=60?bins[2]:n<=80?bins[3]:bins[4];
    rows.forEach((row)=>{riskBins[bin(row.risk_score)]++;confidenceBins[bin(row.confidence_score)]++;});
    const mappings=rows.filter((x)=>x.mitre_tactic_optional);
    const tactics=categoryStats(mappings,'mitre_tactic_optional');
    const topTactics=Object.entries(tactics).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([tactic,count])=>({tactic,label:tactic,count}));
    const techCounts={}; mappings.forEach((x)=>{if(x.mitre_technique_id_optional){const id=x.mitre_technique_id_optional;techCounts[id] ||= {technique:x.mitre_technique_optional,technique_id:id,count:0};techCounts[id].count++;}});
    const topTechniques=Object.values(techCounts).sort((a,b)=>b.count-a.count).slice(0,8);
    const vulnSeverity=categoryStats(vulnerabilities,'severity');
    return {total_threat_records:rows.length,critical_threats:rows.filter((x)=>x.severity==='CRITICAL').length,high_threats:rows.filter((x)=>x.severity==='HIGH').length,
      active_indicators:new Set(rows.filter((x)=>!['CLOSED','FALSE_POSITIVE'].includes(x.status)).map((x)=>x.indicator_value)).size,
      average_confidence:rows.length?Math.round(rows.reduce((sum,x)=>sum+x.confidence_score,0)/rows.length):0,
      vulnerabilities_tracked:vulnerabilities.length, average_risk:rows.length?Math.round(rows.reduce((sum,x)=>sum+x.risk_score,0)/rows.length):0,
      threats_by_severity:severity,threats_by_category:categories,indicator_type_distribution:types,threat_status_distribution:statuses,
      risk_distribution:riskBins,confidence_distribution:confidenceBins,vulnerabilities_by_severity:vulnSeverity,top_attack_tactics:topTactics,top_attack_techniques:topTechniques};
  }
  function getTrends(rows, days) {
    const grouped={}; rows.forEach((row)=>{const day=String(row.timestamp||'').slice(0,10);if(!day)return;grouped[day] ||= {day,observations:0,risk:0};grouped[day].observations++;grouped[day].risk+=row.risk_score;});
    return Object.values(grouped).sort((a,b)=>a.day.localeCompare(b.day)).slice(-days).map((x)=>({day:x.day,observations:x.observations,average_risk:Math.round(x.risk/x.observations)}));
  }
  function sourceSummary(rows) {
    const rel={A:'Highly Reliable',B:'Usually Reliable',C:'Fairly Reliable',D:'Reliability Unknown'};const by={};
    rows.forEach((x)=>{by[x.source_name] ||= {source_name:x.source_name,reliability:x.source_reliability,reliability_label:rel[x.source_reliability]||'Reliability Unknown',record_count:0};by[x.source_name].record_count++;});
    return Object.values(by).sort((a,b)=>b.record_count-a.record_count);
  }
  function scoreQuiz(questions, answers) {
    const totals={}, results=[];let correct=0;
    questions.forEach((q)=>{const selected=answers[q.id];const ok=Number.isInteger(selected)&&selected===Number(q.correct_index);totals[q.category] ||= [0,0];if(ok){correct++;totals[q.category][0]++;}totals[q.category][1]++;results.push({question_id:q.id,category:q.category,selected_index:selected??null,correct_index:Number(q.correct_index),is_correct:ok,explanation:q.explanation||''});});
    const overall=questions.length?Math.round(correct/questions.length*100):0;const label=overall<=40?'Needs Improvement':overall<=60?'Basic Awareness':overall<=80?'Good Awareness':'Strong Awareness';
    const category_scores=Object.fromEntries(Object.entries(totals).map(([key,val])=>[key,Math.round(val[0]/val[1]*100)]));const weakest_areas=Object.keys(category_scores).sort((a,b)=>category_scores[a]-category_scores[b]).slice(0,3);
    const moduleMap={'PHISHING':'phishing-awareness','PASSWORDS':'password-security','MFA':'mfa-basics','SOCIAL ENGINEERING':'social-engineering','SAFE BROWSING':'safe-browsing','RANSOMWARE':'ransomware-awareness','PRIVACY':'data-privacy','WI-FI':'secure-wifi','MOBILE SECURITY':'mobile-security','INCIDENT REPORTING':'incident-reporting'};
    const recommendations=Object.entries(category_scores).sort((a,b)=>a[1]-b[1]).map(([category,score])=>({category,score,module_id:moduleMap[category]||'security-basics',recommendation:score<80?`Review the ${category.toLowerCase()} awareness module.`:'No immediate refresher suggested; revisit during routine learning.',priority:score<80?'FOCUS AREA':'MAINTAIN'}));
    return {overall_score:overall,label,correct_answers:correct,total_questions:questions.length,category_scores,weakest_areas,recommendations,results,educational_notice:'This learning score is for self-reflection only; it is not an employee fitness or competency judgment.'};
  }

  async function staticApi(path, options = {}) {
    const data = await getData();
    const [route, query = ''] = String(path).split('?'); const params = new URLSearchParams(query);
    const method = String(options.method || 'GET').toUpperCase();
    const body = options.body ? JSON.parse(options.body) : {};
    const all = getAllThreats(data); const vulnerabilities=getVulnerabilities(data,new URLSearchParams());
    const getAlertsNow=()=>getAlerts(data,all);

    if (route === '/api/health') return {status:'ok',mode:'GitHub Pages static browser mode',indicator_network_lookups:false,database:'bundled CSV/JSON + browser localStorage'};
    if (route === '/api/dashboard/stats') { const stats=getStats(all,vulnerabilities); const alerts=getAlertsNow();stats.open_investigations=alerts.filter((x)=>['NEW','INVESTIGATING'].includes(x.status)).length;return stats; }
    if (route === '/api/dashboard/trends') return {days:number(params.get('days'),30),items:getTrends(all,Math.min(365,Math.max(1,number(params.get('days'),30))))};
    if (route === '/api/threats' && method === 'GET') {
      const filters={severity:params.get('severity')?.toUpperCase(),category:params.get('category')?.toUpperCase(),indicator_type:params.get('indicator_type')?.toUpperCase(),status:params.get('status')?.toUpperCase(),
        min_risk:number(params.get('min_risk')),max_risk:params.has('max_risk')?number(params.get('max_risk')):100,min_confidence:number(params.get('min_confidence')),max_confidence:params.has('max_confidence')?number(params.get('max_confidence')):100,
        from_date:params.get('from_date'),to_date:params.get('to_date'),q:(params.get('q')||'').toLowerCase(),sort:params.get('sort')||'newest',page:Math.max(1,number(params.get('page'),1)),page_size:Math.min(100,Math.max(1,number(params.get('page_size'),25)))};
      let rows=[...all].filter((x)=>(!filters.severity||x.severity===filters.severity)&&(!filters.category||x.threat_category===filters.category)&&(!filters.indicator_type||x.indicator_type===filters.indicator_type)&&(!filters.status||x.status===filters.status)&&x.risk_score>=filters.min_risk&&x.risk_score<=filters.max_risk&&x.confidence_score>=filters.min_confidence&&x.confidence_score<=filters.max_confidence&&(!filters.from_date||String(x.timestamp).slice(0,10)>=filters.from_date)&&(!filters.to_date||String(x.timestamp).slice(0,10)<=filters.to_date)&&(!filters.q||[x.threat_id,x.threat_name,x.indicator_value,x.description,x.cve_id_optional].some((v)=>String(v||'').toLowerCase().includes(filters.q))));
      const cmpDate=(a,b)=>String(b.timestamp).localeCompare(String(a.timestamp));
      if(filters.sort==='risk')rows.sort((a,b)=>b.risk_score-a.risk_score||cmpDate(a,b));else if(filters.sort==='confidence')rows.sort((a,b)=>b.confidence_score-a.confidence_score||cmpDate(a,b));else if(filters.sort==='observed')rows.sort((a,b)=>b.observed_count-a.observed_count||cmpDate(a,b));else if(filters.sort==='oldest')rows.sort((a,b)=>String(a.timestamp).localeCompare(String(b.timestamp)));else rows.sort(cmpDate);
      const total=rows.length,pages=Math.max(1,Math.ceil(total/filters.page_size)),start=(filters.page-1)*filters.page_size;
      return {items:rows.slice(start,start+filters.page_size),total,page:filters.page,page_size:filters.page_size,pages};
    }
    const threatDetailMatch=route.match(/^\/api\/threats\/([^/]+)$/);
    if (threatDetailMatch && method === 'GET') {const id=decodeURIComponent(threatDetailMatch[1]);const threat=all.find((x)=>x.threat_id===id);if(!threat)throw new Error('Threat record not found in the local browser dataset.');return getThreatDetail(threat,all,getAlertsNow());}
    if (route === '/api/threats' && method === 'POST') {
      const check=validateIndicator(body.indicator_value);if(!check.valid)throw new Error(check.validation_notes);
      const categories=['PHISHING','MALWARE','RANSOMWARE','CREDENTIAL THREATS','WEB THREATS','NETWORK THREATS','VULNERABILITY EXPOSURE','SOCIAL ENGINEERING','DATA EXPOSURE','ACCOUNT SECURITY'];
      if(!categories.includes(String(body.threat_category||'').toUpperCase()))throw new Error('Unsupported threat category.');
      const rows=getAllThreats(data);const id=body.threat_id||`THR-STATIC-${Date.now()}`;if(rows.some((x)=>x.threat_id===id))throw new Error('Threat ID already exists.');
      const risk=clamp(body.risk_score??50),now=new Date().toISOString();const item={threat_id:id,threat_name:String(body.threat_name||'Synthetic observation'),threat_category:String(body.threat_category).toUpperCase(),description:String(body.description||'Synthetic local observation.'),severity:riskBand(risk),risk_score:risk,confidence_score:clamp(body.confidence_score??50),status:String(body.status||'NEW').toUpperCase(),timestamp:now,first_seen:body.first_seen||now,last_seen:body.last_seen||now,indicator_type:check.indicator_type,indicator_value:check.normalized_value,source_name:body.source_name||'Internal SOC',source_reliability:body.source_reliability||'C',country_or_region_optional:'Browser-only demo',mitre_tactic_optional:null,mitre_technique_optional:null,mitre_technique_id_optional:null,cve_id_optional:check.indicator_type==='CVE ID'?check.normalized_value:'',campaign_id:body.campaign_id||'',observed_count:number(body.observed_count,1),synthetic_label:'SYNTHETIC / DEMO ONLY'};
      const additions=readStore('threats',[]);additions.push(item);writeStore('threats',additions);return getThreatDetail(item,getAllThreats(data),getAlertsNow());
    }
    const threatStatusMatch=route.match(/^\/api\/threats\/([^/]+)$/);
    if (threatStatusMatch && method === 'PUT') {const id=decodeURIComponent(threatStatusMatch[1]);if(!all.some((x)=>x.threat_id===id))throw new Error('Threat record not found.');const status=String(body.status||'').toUpperCase();if(!['NEW','UNDER_REVIEW','MONITORING','CLOSED','FALSE_POSITIVE'].includes(status))throw new Error('Unsupported threat status.');const statuses=readStore('threat-statuses',{});statuses[id]=status;writeStore('threat-statuses',statuses);return getThreatDetail(getAllThreats(data).find((x)=>x.threat_id===id),getAllThreats(data),getAlertsNow());}
    if (route === '/api/indicators/search' && method === 'GET') return searchIndicator(params.get('q')||'',data,all,getAlertsNow());
    if (route === '/api/alerts' && method === 'GET') {const rows=getAlertsNow().filter((x)=>(!params.get('status')||x.status===params.get('status').toUpperCase())&&(!params.get('severity')||x.severity===params.get('severity').toUpperCase())).sort((a,b)=>b.risk_score-a.risk_score||String(b.timestamp).localeCompare(String(a.timestamp))).slice(0,Math.min(500,Math.max(1,number(params.get('limit'),100))));return {items:rows,total_returned:rows.length};}
    const alertStatusMatch=route.match(/^\/api\/alerts\/([^/]+)\/status$/);
    if(alertStatusMatch&&method==='PUT'){const id=decodeURIComponent(alertStatusMatch[1]);const status=String(body.status||'').toUpperCase();if(!['NEW','INVESTIGATING','MONITORING','RESOLVED','FALSE_POSITIVE'].includes(status))throw new Error('Unsupported alert status.');const alerts=getAlertsNow();const target=alerts.find((x)=>x.alert_id===id);if(!target)throw new Error('Alert not found.');target.status=status;writeStore('alerts',alerts);return target;}
    const noteMatch=route.match(/^\/api\/threats\/([^/]+)\/notes$/);
    if(noteMatch&&method==='POST'){const id=decodeURIComponent(noteMatch[1]);if(!all.some((x)=>x.threat_id===id))throw new Error('Threat record not found.');const note=String(body.note||'').trim();if(note.length<3||note.length>1000)throw new Error('Note must be between 3 and 1,000 characters.');const notes=getNotes();notes[id] ||= [];const item={note_id:`NOTE-STATIC-${Date.now()}`,threat_id:id,note,created_at:new Date().toISOString(),author_label:body.author_label||'LOCAL ANALYST'};notes[id].unshift(item);writeStore('notes',notes);return item;}
    if (route === '/api/vulnerabilities') {const items=getVulnerabilities(data,params);return {items,total:items.length,synthetic_notice:'All vulnerability rows are fictional classroom scenarios; no real CVE advisory is represented.'};}
    if (route === '/api/awareness/modules') return {items:data.modules,total:data.modules.length};
    const moduleMatch=route.match(/^\/api\/awareness\/modules\/([^/]+)$/);if(moduleMatch){const item=data.modules.find((x)=>x.id===decodeURIComponent(moduleMatch[1]));if(!item)throw new Error('Awareness module not found.');return item;}
    if(route==='/api/quiz'&&method==='GET')return {total:data.quiz.length,questions:data.quiz.map(({id,category,module_id,question,options})=>({id,category,module_id,question,options}))};
    if(route==='/api/quiz/submit'&&method==='POST'){const answers=body.answers||{};const known=new Set(data.quiz.map((q)=>q.id));for(const [id,index]of Object.entries(answers))if(!known.has(id)||!Number.isInteger(index)||index<0||index>3)throw new Error('Unknown question or invalid answer option.');const result=scoreQuiz(data.quiz,answers);const history=readStore('quiz-history',[]);const saved={...result,result_id:`STATIC-${Date.now()}`,created_at:new Date().toISOString()};history.unshift(saved);writeStore('quiz-history',history);return saved;}
    if(route==='/api/awareness/score'){const history=readStore('quiz-history',[]);return {latest:history[0]?{overall_score:history[0].overall_score,category_scores:history[0].category_scores,created_at:history[0].created_at}:null,history:history.slice(0,12),notice:'Awareness scores are educational self-reflection, not employee competency judgments.'};}
    if(route==='/api/attack/tactics'){const stats=getStats(all,vulnerabilities);return {tactics:stats.top_attack_tactics,techniques:stats.top_attack_techniques,mapping_notice:'Mappings are included only where synthetic behavior context supports them; an IOC alone is not a technique.'};}
    const techniqueMatch=route.match(/^\/api\/attack\/techniques\/([^/]+)\/threats$/);if(techniqueMatch){const id=decodeURIComponent(techniqueMatch[1]);const items=all.filter((x)=>x.mitre_technique_id_optional===id).sort((a,b)=>b.risk_score-a.risk_score).slice(0,200);return {technique_id:id,items,total:items.length,attribution:'NOT ESTABLISHED'};}
    if(route==='/api/executive/summary'){
      const stats=getStats(all,vulnerabilities),alerts=getAlertsNow(),history=readStore('quiz-history',[]),highCritical=stats.critical_threats+stats.high_threats;
      const openHigh=alerts.filter((x)=>['HIGH','CRITICAL'].includes(x.severity)&&['NEW','INVESTIGATING','MONITORING'].includes(x.status)).length;
      const installed=new Set(data.assets.flatMap((a)=>(a.software_list||[]).map((s)=>String(s.name).toLowerCase())));
      const affected=vulnerabilities.filter((v)=>v.exploitation_status_demo==='YES'&&installed.has(String(v.product_category).toLowerCase()));
      const cohort=data.awarenessMetrics,alertPressure=Math.min(100,openHigh*12),vulnPressure=Math.min(100,affected.length*25),awarenessGap=clamp(100-number(cohort.completion_rate));
      const score=Math.round(alertPressure*.4+vulnPressure*.4+awarenessGap*.2),categories=Object.entries(stats.threats_by_category).sort((a,b)=>b[1]-a[1]).slice(0,3),topVulns=[...new Set(vulnerabilities.sort((a,b)=>b.priority_score-a.priority_score).slice(0,4).map((x)=>x.product_category))];
      const focus=[];if(highCritical)focus.push('Review high/critical synthetic alerts with an analyst before taking action.');if(affected.length)focus.push('Validate synthetic asset inventory matches and patch plans for scenarios marked with demo exploitation evidence.');if(!history.length)focus.push('Invite learners to complete the self-guided quiz; no awareness result is recorded yet.');if(!focus.length)focus.push('Maintain routine monitoring, patch review, and short awareness refreshers.');
      return {label:'ILLUSTRATIVE SYNTHETIC DEMO SUMMARY',plain_language_summary:`The local dataset contains ${all.length.toLocaleString()} fictional observations. ${highCritical.toLocaleString()} are currently scored high or critical for review; none is a confirmed incident by score alone.`,illustrative_organizational_risk_score:score,score_components:{alert_pressure_40_percent:alertPressure,demo_vulnerability_context_40_percent:vulnPressure,awareness_completion_gap_20_percent:awarenessGap},high_critical_threat_count:highCritical,high_critical_alert_count:openHigh,known_exploited_demo_cves_affecting_assets:affected.length,awareness_completion_rate_demo:cohort.completion_rate,awareness_cohort_demo:{enrolled_learners:cohort.enrolled_learners,completed_learners:cohort.completed_learners,cohort_label:cohort.cohort_label},open_investigations:alerts.filter((x)=>['NEW','INVESTIGATING'].includes(x.status)).length,top_threat_categories:categories.map(([category,records])=>({category,records})),top_vulnerability_categories:topVulns,awareness_latest_score:history[0]?.overall_score??null,awareness_score_trend:history.slice(0,12),top_awareness_weaknesses:history[0]?.category_scores||{},recommended_defensive_priorities:focus,metrics:{alerts_in_review_queue:alerts.filter((x)=>['NEW','INVESTIGATING'].includes(x.status)).length,synthetic_vulnerability_scenarios:vulnerabilities.length,awareness_completion_rate_demo:cohort.completion_rate}};
    }
    if(route==='/api/sources')return {items:sourceSummary(all),reliability_note:'Source reliability describes a source\'s historical quality; item confidence describes evidence for this specific record.'};
    if(route==='/api/system/guide')return {classification:{observation:'A logged event or report that needs context.',indicator:'An artifact such as an IP, domain, URL, hash, or CVE used for correlation.',alert:'A rule-generated request for analyst review.',threat:'An assessed potential risk with supporting context.',incident:'A confirmed or formally declared security event under organizational process.'},safety:['No indicator is visited or resolved','Hashes are never used to locate or execute files','Risk is not confidence','An IOC match is not proof of compromise','ATT&CK mapping requires behavior context'],database_design:['threats → indicators: one or more observed artifacts','sources → threats: origin and source reliability','threats → attack_mappings: optional behavior mapping','threats → alerts/analyst_notes: investigation workflow','quiz_results → awareness score history','vulnerabilities: synthetic prioritization scenarios']};
    throw new Error(`Static demo adapter does not recognize ${method} ${route}`);
  }

  function searchIndicator(value,data,all,alerts){
    const validation=validateIndicator(value);if(!validation.valid)return {...validation,known_in_demo_dataset:false,threat_count:0,matches:[],interpretation:validation.validation_notes};
    const needle=validation.normalized_value.toLowerCase();const matches=all.filter((x)=>String(x.indicator_value).toLowerCase()===needle||String(x.cve_id_optional||'').toLowerCase()===needle);
    const ids=new Set(matches.map((x)=>x.threat_id));const campaigns=new Set(matches.map((x)=>x.campaign_id).filter(Boolean));const related=all.filter((x)=>!ids.has(x.threat_id)&&x.campaign_id&&campaigns.has(x.campaign_id));
    const matchAlerts=alerts.filter((x)=>ids.has(x.threat_id)||String(x.indicator_value).toLowerCase()===needle);const notes=matches.flatMap((x)=>getNotes()[x.threat_id]||[]);const signals=data.signals.filter((x)=>String(x.indicator_value).toLowerCase()===needle);
    if(!matches.length)return {...validation,known_in_demo_dataset:false,threat_count:0,first_seen:null,last_seen:null,categories:[],confidence_score:null,risk_score:null,severity:null,status:null,source_names:[],source_reliability:null,related_alerts:matchAlerts,related_indicators:[],mitre_mappings:[],analyst_notes:notes,internal_sightings:signals,interpretation:'No exact match in the local synthetic dataset. This is not an external reputation lookup.',matches:[]};
    const latest=[...matches].sort((a,b)=>String(b.last_seen).localeCompare(String(a.last_seen)))[0];const max=(key)=>Math.max(...matches.map((x)=>number(x[key])));const minDate=(key)=>matches.map((x)=>String(x[key]||'')).sort()[0];const maxDate=(key)=>matches.map((x)=>String(x[key]||'')).sort().at(-1);
    const maps=[];matches.forEach((x)=>{if(x.mitre_tactic_optional||x.mitre_technique_optional){const m={tactic:x.mitre_tactic_optional,technique:x.mitre_technique_optional,technique_id:x.mitre_technique_id_optional,threat_id:x.threat_id};if(!maps.some((y)=>JSON.stringify(y)===JSON.stringify(m)))maps.push(m);}});
    return {...validation,known_in_demo_dataset:true,threat_count:matches.length,first_seen:minDate('first_seen'),last_seen:maxDate('last_seen'),categories:[...new Set(matches.map((x)=>x.threat_category))].sort(),confidence_score:max('confidence_score'),risk_score:max('risk_score'),severity:latest.severity,status:latest.status,source_names:[...new Set(matches.map((x)=>x.source_name))].sort(),source_reliability:latest.source_reliability,related_alerts:matchAlerts,related_indicators:[...new Set(related.map((x)=>x.indicator_value))],mitre_mappings:maps,analyst_notes:notes,internal_sightings:signals,interpretation:'Local synthetic-data match only; an indicator match does not establish compromise or attribution.',matches:matches.map((x)=>({threat_id:x.threat_id,threat_name:x.threat_name,category:x.threat_category,severity:x.severity,risk_score:x.risk_score,confidence_score:x.confidence_score,status:x.status,first_seen:x.first_seen,last_seen:x.last_seen}))};
  }

  window.SignalAtlasStaticApi = staticApi;
})();
