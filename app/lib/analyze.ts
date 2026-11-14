// Rule-based scam detector used by the ScamShield UI.
// Kept free of React/DOM imports so it can be unit-tested with `node --test`.

export type Result = { score:number; level:'Safe'|'Suspicious'|'Dangerous'; summary:string; signs:string[]; links:string[]; actions:string[]; matches:string[] };

// Latin-script keywords must start at a word boundary so that e.g. "invite" does
// not match "vite" and "repay" does not match "pay". Suffixes stay allowed so
// plurals ("prizes", "passwords") still match. Arabic terms are matched as-is.
const words = (latin:string, other?:string) =>
  new RegExp(`(?<![\\p{L}\\p{N}])(?:${latin})${other ? `|${other}` : ''}`, 'giu');

const rules = [
  {re:words('urgent|immediately|act now|today|suspend|blocked|dernier avertissement|vite\\b','عاجل|حالاً|ديركت'),pts:18,label:'Pressure or urgent language'},
  {re:/\b(?:password|mot de passe|pin|otp|verification code)\b|كلمة السر|رمز|كود/gi,pts:25,label:'Requests sensitive security information'},
  {re:words('prize|winner|giveaway|lottery|cadeau|gagné','ربحت|هدية'),pts:20,label:'Unexpected prize or giveaway'},
  {re:words('send money|pay|payment|transfer|wire|crypto|gift card','ادفع|حوّل|خلص'),pts:18,label:'Requests money or payment'},
  {re:words('remote job|easy income|work from home|visa(?!ge)|immigration|scholarship|emploi|bourse','منحة|فيزا'),pts:16,label:'High-risk offer or opportunity'},
  {re:words('algérie poste|algerie poste|baridimob|edahabia|mobilis|djezzy|ooredoo|bank|government|delivery|parcel|colis|banque','بريد|طرد'),pts:9,label:'Impersonates a trusted organization'},
  {re:words('fear|police|legal action|arrest|account closed|compte fermé','غلق الحساب|متابعة'),pts:17,label:'Fear or threat tactics'},
];

const SHORTENER_HOSTS = /^(?:www\.)?(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|shorturl\.at|is\.gd|goo\.gl|ow\.ly|rb\.gy)$/i;

function hostnameOf(raw:string):string {
  try { return new URL(/^https?:\/\//i.test(raw) ? raw : `http://${raw}`).hostname; } catch { return ''; }
}

export function analyze(text:string):Result {
  let score=3; const signs:string[]=[]; const matches:string[]=[];
  const urls=text.match(/(?:https?:\/\/|www\.)[^\s<]+/gi)||[];
  const prose=text.replace(/(?:https?:\/\/|www\.)[^\s<]+/gi,' ');
  for(const rule of rules){ const found=prose.match(rule.re); if(found){ score+=rule.pts; signs.push(rule.label); matches.push(...found); }}
  for(const raw of urls){
    if(/^http:\/\//i.test(raw)){score+=14; signs.push('Link does not use secure HTTPS');}
    if(SHORTENER_HOSTS.test(hostnameOf(raw))){score+=18;signs.push('Shortened link hides its destination');}
    if(/https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i.test(raw)){score+=24;signs.push('Link uses a raw IP address');}
    if(/\.(?:top|xyz|click|work|zip|mov|exe)(?:[/?]|$)/i.test(raw)){score+=20;signs.push('Unusual or dangerous domain/file type');}
    if(/(?:algerie|baridi|mobilis|djezzy|ooredoo)[.-].*\.(?:top|xyz|click)/i.test(raw)){score+=20;signs.push('Domain may imitate a known organization');}
  }
  if(/[!]{2,}|[A-Z]{8,}/.test(text)){score+=7;signs.push('Aggressive formatting');}
  score=Math.min(100,score); const level=score>=65?'Dangerous':score>=28?'Suspicious':'Safe';
  const summary=level==='Dangerous'?'This content shows several strong signs of phishing or fraud.':level==='Suspicious'?'This content has warning signs that deserve careful verification.':'No strong scam signals were found, but stay cautious.';
  const actions=level==='Safe'?['Verify unexpected requests through an official channel','Never share passwords or one-time codes','Stay alert if the sender applies pressure']:['Do not click the link or reply','Do not share personal or banking information','Contact the organization using its official website','Block and report the sender',...(score>=65?['Change exposed passwords and enable two-factor authentication','Contact your bank immediately if you shared payment details']:[])];
  return {score,level,summary,signs:[...new Set(signs)],links:urls,actions,matches:[...new Set(matches.map(x=>x.toLowerCase()))]};
}
