/**
 * @veil/device — display names other people chose (group nicknames, thread
 * titles). b71 (audit): a name could hide characters that render as nothing
 * (zero-width spaces, joiners, bidi controls, soft hyphens, tag characters),
 * use letters from another script that look like Latin ones, or reorder the
 * text around it with bidi controls. Names are cleaned before they are shown
 * or compared, compared on a look-alike "skeleton", and shown isolated so they
 * can't reorder the text next to them.
 * b75 (audit GR-4): the skeleton folds a compact UTS #39 confusables subset after dropping
 * every combining mark; names that mix scripts, use a script outside the common set, claim
 * a role word or carry another member's ID prefix are flagged (nameRisk), and every dot-like
 * character that could pass for the app's " · ID" separator is replaced (displayGroupName).
 *
 * No Unicode property escapes on purpose: the RN JS engine's support for
 * binary Unicode properties varies, and a regex that fails to compile would
 * stop the module loading. The ranges below are Unicode 15's
 * Default_Ignorable_Code_Point set plus the format (Cf) characters and the
 * line/paragraph separators.
 */

const INVISIBLE = new RegExp(
  '[' +
    '\\u00AD\\u034F\\u061C\\u115F\\u1160\\u17B4\\u17B5\\u180B-\\u180F' +
    '\\u200B-\\u200F\\u2028-\\u202E\\u2060-\\u206F\\u3164\\uFE00-\\uFE0F\\uFEFF\\uFFA0\\uFFF0-\\uFFFB' +
    '\\u0600-\\u0605\\u06DD\\u070F\\u0890\\u0891\\u08E2' +
  ']|[\\u{110BD}\\u{110CD}\\u{13430}-\\u{1343F}\\u{1BCA0}-\\u{1BCA3}\\u{1D173}-\\u{1D17A}\\u{E0000}-\\u{E0FFF}]',
  'gu',
);
/** characters that render as a blank (folded to a plain space) */
const BLANKS = /[⠀　  -    ]/gu;

/** remove characters that render as nothing; blanks become a plain space */
export function stripInvisible(s: string): string {
  return String(s ?? '').replace(INVISIBLE, '').replace(BLANKS, ' ');
}

/**
 * b77u (audit 6 IH full L-12): check marks and their look-alikes (✓ ✔ ✅ ☑ √ ⍻ 🗸 🗹 and the Aegean check mark).
 * The app draws its own ✓ after a verified name, in the same line, so "Alice ✓" passed every name guard and wore
 * the verified mark. They are removed from every name shown (cleanName) and from the comparison key (nameSkeleton),
 * flagged by nameRisk, and refused in a name typed on this phone (groupNameProblem).
 */
// b77u2 (UC info): + U+1FBB1 (Symbols for Legacy Computing's check mark)
const CHECK_CLASS = '[✓✔✅☑√⍻\\u{10102}\\u{1F5F8}\\u{1F5F9}\\u{1FBB1}]';
const HAS_CHECK_MARK = new RegExp(CHECK_CLASS, 'u');
export function hasCheckMark(s: string): boolean {
  return HAS_CHECK_MARK.test(stripInvisible(String(s ?? '')).normalize('NFKC'));
}

/** a name as it should be shown: no invisible characters, no check marks (b77u L-12), single spaces, trimmed */
export function cleanName(s: string): string {
  return stripInvisible(s).normalize('NFC').replace(checkRun(), '').replace(/\s+/g, ' ').trim();
}

/**
 * Show a name inside FIRST STRONG ISOLATE … POP DIRECTIONAL ISOLATE, so a
 * right-to-left name can't reorder the text around it. Any isolate or embedding
 * the name itself carried was removed by cleanName.
 */
export function isolateName(s: string): string {
  const c = cleanName(s);
  return c ? '⁨' + c + '⁩' : c;
}

/** b75 (audit RT-7): characters of a Vardum ID shown in an unverified title. 8 base58
 *  characters (~47 bits) could be matched by grinding identity keys; 12 (~70 bits) cannot.
 *  b77s (audit 4 GR-02): also the length of the " · ID" suffix that tells two group members with
 *  the same name apart (it was 8). */
export const UNVERIFIED_ID_CHARS = 12;

/** b71: a thread from a Vardum ID this phone hasn't pinned (never the sender's own name) */
export function unverifiedTitle(veilId: string | null | undefined): string {
  const id = cleanName(String(veilId ?? ''));
  if (!id) return 'Unknown sender (unverified)';
  return id.length > UNVERIFIED_ID_CHARS ? `${id.slice(0, UNVERIFIED_ID_CHARS)}… (unverified)` : `${id} (unverified)`;
}

// b75 (audit GR-4): generated from the Unicode 15 character database (general categories Mn, Me, Mc):
// every combining mark. Dropped from a name before it is compared (nameSkeleton, nameRisk).
const MARKS = new RegExp('[' +
  '\\u{300}-\\u{36F}\\u{483}-\\u{489}\\u{591}-\\u{5BD}\\u{5BF}\\u{5C1}-\\u{5C2}\\u{5C4}-\\u{5C5}' +
  '\\u{5C7}\\u{610}-\\u{61A}\\u{64B}-\\u{65F}\\u{670}\\u{6D6}-\\u{6DC}\\u{6DF}-\\u{6E4}\\u{6E7}-' +
  '\\u{6E8}\\u{6EA}-\\u{6ED}\\u{711}\\u{730}-\\u{74A}\\u{7A6}-\\u{7B0}\\u{7EB}-\\u{7F3}\\u{7FD}' +
  '\\u{816}-\\u{819}\\u{81B}-\\u{823}\\u{825}-\\u{827}\\u{829}-\\u{82D}\\u{859}-\\u{85B}\\u{898}-' +
  '\\u{89F}\\u{8CA}-\\u{8E1}\\u{8E3}-\\u{903}\\u{93A}-\\u{93C}\\u{93E}-\\u{94F}\\u{951}-\\u{957}' +
  '\\u{962}-\\u{963}\\u{981}-\\u{983}\\u{9BC}\\u{9BE}-\\u{9C4}\\u{9C7}-\\u{9C8}\\u{9CB}-\\u{9CD}' +
  '\\u{9D7}\\u{9E2}-\\u{9E3}\\u{9FE}\\u{A01}-\\u{A03}\\u{A3C}\\u{A3E}-\\u{A42}\\u{A47}-\\u{A48}' +
  '\\u{A4B}-\\u{A4D}\\u{A51}\\u{A70}-\\u{A71}\\u{A75}\\u{A81}-\\u{A83}\\u{ABC}\\u{ABE}-\\u{AC5}' +
  '\\u{AC7}-\\u{AC9}\\u{ACB}-\\u{ACD}\\u{AE2}-\\u{AE3}\\u{AFA}-\\u{AFF}\\u{B01}-\\u{B03}\\u{B3C}' +
  '\\u{B3E}-\\u{B44}\\u{B47}-\\u{B48}\\u{B4B}-\\u{B4D}\\u{B55}-\\u{B57}\\u{B62}-\\u{B63}\\u{B82}' +
  '\\u{BBE}-\\u{BC2}\\u{BC6}-\\u{BC8}\\u{BCA}-\\u{BCD}\\u{BD7}\\u{C00}-\\u{C04}\\u{C3C}\\u{C3E}-' +
  '\\u{C44}\\u{C46}-\\u{C48}\\u{C4A}-\\u{C4D}\\u{C55}-\\u{C56}\\u{C62}-\\u{C63}\\u{C81}-\\u{C83}' +
  '\\u{CBC}\\u{CBE}-\\u{CC4}\\u{CC6}-\\u{CC8}\\u{CCA}-\\u{CCD}\\u{CD5}-\\u{CD6}\\u{CE2}-\\u{CE3}' +
  '\\u{CF3}\\u{D00}-\\u{D03}\\u{D3B}-\\u{D3C}\\u{D3E}-\\u{D44}\\u{D46}-\\u{D48}\\u{D4A}-\\u{D4D}' +
  '\\u{D57}\\u{D62}-\\u{D63}\\u{D81}-\\u{D83}\\u{DCA}\\u{DCF}-\\u{DD4}\\u{DD6}\\u{DD8}-\\u{DDF}' +
  '\\u{DF2}-\\u{DF3}\\u{E31}\\u{E34}-\\u{E3A}\\u{E47}-\\u{E4E}\\u{EB1}\\u{EB4}-\\u{EBC}\\u{EC8}-' +
  '\\u{ECE}\\u{F18}-\\u{F19}\\u{F35}\\u{F37}\\u{F39}\\u{F3E}-\\u{F3F}\\u{F71}-\\u{F84}\\u{F86}-\\u{F87}' +
  '\\u{F8D}-\\u{F97}\\u{F99}-\\u{FBC}\\u{FC6}\\u{102B}-\\u{103E}\\u{1056}-\\u{1059}\\u{105E}-\\u{1060}' +
  '\\u{1062}-\\u{1064}\\u{1067}-\\u{106D}\\u{1071}-\\u{1074}\\u{1082}-\\u{108D}\\u{108F}\\u{109A}-' +
  '\\u{109D}\\u{135D}-\\u{135F}\\u{1712}-\\u{1715}\\u{1732}-\\u{1734}\\u{1752}-\\u{1753}\\u{1772}-' +
  '\\u{1773}\\u{17B4}-\\u{17D3}\\u{17DD}\\u{180B}-\\u{180D}\\u{180F}\\u{1885}-\\u{1886}\\u{18A9}' +
  '\\u{1920}-\\u{192B}\\u{1930}-\\u{193B}\\u{1A17}-\\u{1A1B}\\u{1A55}-\\u{1A5E}\\u{1A60}-\\u{1A7C}' +
  '\\u{1A7F}\\u{1AB0}-\\u{1ACE}\\u{1B00}-\\u{1B04}\\u{1B34}-\\u{1B44}\\u{1B6B}-\\u{1B73}\\u{1B80}-' +
  '\\u{1B82}\\u{1BA1}-\\u{1BAD}\\u{1BE6}-\\u{1BF3}\\u{1C24}-\\u{1C37}\\u{1CD0}-\\u{1CD2}\\u{1CD4}-' +
  '\\u{1CE8}\\u{1CED}\\u{1CF4}\\u{1CF7}-\\u{1CF9}\\u{1DC0}-\\u{1DFF}\\u{20D0}-\\u{20F0}\\u{2CEF}-' +
  '\\u{2CF1}\\u{2D7F}\\u{2DE0}-\\u{2DFF}\\u{302A}-\\u{302F}\\u{3099}-\\u{309A}\\u{A66F}-\\u{A672}' +
  '\\u{A674}-\\u{A67D}\\u{A69E}-\\u{A69F}\\u{A6F0}-\\u{A6F1}\\u{A802}\\u{A806}\\u{A80B}\\u{A823}-' +
  '\\u{A827}\\u{A82C}\\u{A880}-\\u{A881}\\u{A8B4}-\\u{A8C5}\\u{A8E0}-\\u{A8F1}\\u{A8FF}\\u{A926}-' +
  '\\u{A92D}\\u{A947}-\\u{A953}\\u{A980}-\\u{A983}\\u{A9B3}-\\u{A9C0}\\u{A9E5}\\u{AA29}-\\u{AA36}' +
  '\\u{AA43}\\u{AA4C}-\\u{AA4D}\\u{AA7B}-\\u{AA7D}\\u{AAB0}\\u{AAB2}-\\u{AAB4}\\u{AAB7}-\\u{AAB8}' +
  '\\u{AABE}-\\u{AABF}\\u{AAC1}\\u{AAEB}-\\u{AAEF}\\u{AAF5}-\\u{AAF6}\\u{ABE3}-\\u{ABEA}\\u{ABEC}-' +
  '\\u{ABED}\\u{FB1E}\\u{FE00}-\\u{FE0F}\\u{FE20}-\\u{FE2F}\\u{101FD}\\u{102E0}\\u{10376}-\\u{1037A}' +
  '\\u{10A01}-\\u{10A03}\\u{10A05}-\\u{10A06}\\u{10A0C}-\\u{10A0F}\\u{10A38}-\\u{10A3A}\\u{10A3F}' +
  '\\u{10AE5}-\\u{10AE6}\\u{10D24}-\\u{10D27}\\u{10EAB}-\\u{10EAC}\\u{10EFD}-\\u{10EFF}\\u{10F46}-' +
  '\\u{10F50}\\u{10F82}-\\u{10F85}\\u{11000}-\\u{11002}\\u{11038}-\\u{11046}\\u{11070}\\u{11073}-' +
  '\\u{11074}\\u{1107F}-\\u{11082}\\u{110B0}-\\u{110BA}\\u{110C2}\\u{11100}-\\u{11102}\\u{11127}-' +
  '\\u{11134}\\u{11145}-\\u{11146}\\u{11173}\\u{11180}-\\u{11182}\\u{111B3}-\\u{111C0}\\u{111C9}-' +
  '\\u{111CC}\\u{111CE}-\\u{111CF}\\u{1122C}-\\u{11237}\\u{1123E}\\u{11241}\\u{112DF}-\\u{112EA}' +
  '\\u{11300}-\\u{11303}\\u{1133B}-\\u{1133C}\\u{1133E}-\\u{11344}\\u{11347}-\\u{11348}\\u{1134B}-' +
  '\\u{1134D}\\u{11357}\\u{11362}-\\u{11363}\\u{11366}-\\u{1136C}\\u{11370}-\\u{11374}\\u{11435}-' +
  '\\u{11446}\\u{1145E}\\u{114B0}-\\u{114C3}\\u{115AF}-\\u{115B5}\\u{115B8}-\\u{115C0}\\u{115DC}-' +
  '\\u{115DD}\\u{11630}-\\u{11640}\\u{116AB}-\\u{116B7}\\u{1171D}-\\u{1172B}\\u{1182C}-\\u{1183A}' +
  '\\u{11930}-\\u{11935}\\u{11937}-\\u{11938}\\u{1193B}-\\u{1193E}\\u{11940}\\u{11942}-\\u{11943}' +
  '\\u{119D1}-\\u{119D7}\\u{119DA}-\\u{119E0}\\u{119E4}\\u{11A01}-\\u{11A0A}\\u{11A33}-\\u{11A39}' +
  '\\u{11A3B}-\\u{11A3E}\\u{11A47}\\u{11A51}-\\u{11A5B}\\u{11A8A}-\\u{11A99}\\u{11C2F}-\\u{11C36}' +
  '\\u{11C38}-\\u{11C3F}\\u{11C92}-\\u{11CA7}\\u{11CA9}-\\u{11CB6}\\u{11D31}-\\u{11D36}\\u{11D3A}' +
  '\\u{11D3C}-\\u{11D3D}\\u{11D3F}-\\u{11D45}\\u{11D47}\\u{11D8A}-\\u{11D8E}\\u{11D90}-\\u{11D91}' +
  '\\u{11D93}-\\u{11D97}\\u{11EF3}-\\u{11EF6}\\u{11F00}-\\u{11F01}\\u{11F03}\\u{11F34}-\\u{11F3A}' +
  '\\u{11F3E}-\\u{11F42}\\u{13440}\\u{13447}-\\u{13455}\\u{16AF0}-\\u{16AF4}\\u{16B30}-\\u{16B36}' +
  '\\u{16F4F}\\u{16F51}-\\u{16F87}\\u{16F8F}-\\u{16F92}\\u{16FE4}\\u{16FF0}-\\u{16FF1}\\u{1BC9D}-' +
  '\\u{1BC9E}\\u{1CF00}-\\u{1CF2D}\\u{1CF30}-\\u{1CF46}\\u{1D165}-\\u{1D169}\\u{1D16D}-\\u{1D172}' +
  '\\u{1D17B}-\\u{1D182}\\u{1D185}-\\u{1D18B}\\u{1D1AA}-\\u{1D1AD}\\u{1D242}-\\u{1D244}\\u{1DA00}-' +
  '\\u{1DA36}\\u{1DA3B}-\\u{1DA6C}\\u{1DA75}\\u{1DA84}\\u{1DA9B}-\\u{1DA9F}\\u{1DAA1}-\\u{1DAAF}' +
  '\\u{1E000}-\\u{1E006}\\u{1E008}-\\u{1E018}\\u{1E01B}-\\u{1E021}\\u{1E023}-\\u{1E024}\\u{1E026}-' +
  '\\u{1E02A}\\u{1E08F}\\u{1E130}-\\u{1E136}\\u{1E2AE}\\u{1E2EC}-\\u{1E2EF}\\u{1E4EC}-\\u{1E4EF}' +
  '\\u{1E8D0}-\\u{1E8D6}\\u{1E944}-\\u{1E94A}\\u{E0100}-\\u{E01EF}' +
']', 'gu');
/** b77u2 (UC info): a check mark and the combining marks after it ("✓̶" left a stray stroke behind) */
let CHECK_RUN: RegExp | null = null;
function checkRun(): RegExp {
  if (!CHECK_RUN) CHECK_RUN = new RegExp(`${CHECK_CLASS}${MARKS.source}*`, 'gu');
  CHECK_RUN.lastIndex = 0;
  return CHECK_RUN;
}
/** b75 (audit GR-4): every character Unicode names as a dot, bullet, word separator or full stop
 *  (FULL STOP itself and its width variants excepted), plus the middle-dot shapes — see displayGroupName */
const SEPARATOR_LOOKALIKES = new RegExp('[' +
  '\\u{B7}\\u{2D1}\\u{2D9}\\u{387}\\u{589}\\u{61E}\\u{660}\\u{6D4}\\u{6F0}\\u{701}-\\u{702}\\u{887}-' +
  '\\u{888}\\u{E4F}\\u{F03}\\u{F07}\\u{F0B}-\\u{F0C}\\u{F0F}-\\u{F10}\\u{F14}\\u{FD2}\\u{10FB}' +
  '\\u{1361}-\\u{1362}\\u{1427}\\u{166E}\\u{16EB}\\u{1803}\\u{1809}\\u{18DF}\\u{2022}-\\u{2023}' +
  '\\u{2027}\\u{2041}\\u{2219}\\u{2299}\\u{22C5}\\u{23FA}\\u{25CF}\\u{25D8}\\u{25E6}\\u{26AB}\\u{2981}' +
  '\\u{29BF}\\u{2A00}\\u{2B24}\\u{2CF9}\\u{2CFE}\\u{2D70}\\u{2E30}-\\u{2E31}\\u{2E33}\\u{2E3C}\\u{2E4E}' +
  '\\u{30FB}\\u{A4F8}\\u{A4FF}\\u{A60E}\\u{A6F3}\\u{A718}-\\u{A719}\\u{A78F}\\u{FF65}\\u{10101}' +
  '\\u{1091F}\\u{10A50}\\u{10AF4}\\u{11049}-\\u{1104A}\\u{111C8}\\u{1123A}\\u{115C4}\\u{11A9A}' +
  '\\u{11C43}\\u{11F49}-\\u{11F4B}\\u{16AF5}\\u{16E98}\\u{1BC84}\\u{1BC94}\\u{1BC9F}' +
  '\\u{119E}\\u{318D}' + // Hangul araea (a lone dot)
']', 'gu');

/**
 * b75 (audit GR-4): look-alike letters, folded to one Latin form before names are compared.
 * A compact, hand-picked subset of the Unicode confusables data (UTS #39 confusables.txt,
 * Latin targets) for the scripts people's names are written in: Cyrillic, Greek, Armenian,
 * Latin small capitals / IPA / letters with a stroke, the digit zero of the Indic and
 * South-East Asian scripts, a few Hebrew and Arabic letters, and the Latin-shaped letters of
 * Cherokee, Lisu and Coptic. It is NOT the full table (that is ~6,000 entries); a name using a
 * script outside the common set, or mixing scripts, is flagged instead (nameRisk), so a gap in
 * this table can't make a look-alike pass as plain. Applied after NFKC and after every combining
 * mark is dropped, and BEFORE lower-casing (case matters: Latin capital I and small l look
 * alike, Cyrillic І is a capital I). Values are Latin; lower-casing then gives the skeleton.
 * (b71 kept two smaller Latin/Cyrillic/Greek tables here; both are merged into this one.)
 */
const CONFUSABLE: Record<string, string> = Object.create(null);
function conf(pairs: string): void {
  // "<char><latin> <char><latin> ..." — the first code point maps to the rest
  for (const p of pairs.trim().split(/\s+/)) {
    const cps = [...p];
    CONFUSABLE[cps[0]] = cps.slice(1).join('');
  }
}
// Latin capital I reads as small l; digits and a bar that read as letters
conf('Il 0o 1l |l 5s');
// Latin small capitals, IPA and letters with a stroke (none of these decompose under NFD)
conf('ᴀa ʙb ᴄc ᴅd ᴇe ꜰf ɢg ʜh ɪi ᴊj ᴋk ʟl ᴍm ɴn ᴏo ᴘp ꞯq ʀr ꜱs ᴛt ᴜu ᴠv ᴡw ʏy ᴢz');
conf('ɑa ıi ȷj ɩi ɡg ǀl ɾr øo ØO đd ĐD ħh ĦH łl ŁL ŧt ŦT ƀb ɨi ʉu ɍr ɏy');
// Cyrillic
conf('АA ВB ЕE КK МM НH ОO РP СC ТT ХX УY ЅS Іl Ӏl ЈJ ԚQ ԜW ҮY ҺH ԌG ѴV ѠW ЬB Ꙇl ꙄS');
conf('аa вb еe кk мm нh оo рp сc тt уy хx іi јj ѕs ԁd һh ԛq ԝw ӏl үy ѵv ѡw ԍg ьb пn гr ҽe ꙇi ꙅs');
// Greek
conf('ΑA ΒB ΕE ΖZ ΗH Ιl ΚK ΜM ΝN ΟO ΡP ΤT ΥY ΧX ϹC ϿJ ϒY ϜF');
conf('αa βb γy εe ηn ιi κk νv οo ρp τt υu χx ωw ϲc ϳj ςc σo ϱp ϐb');
// Armenian
conf('ՕO օo ՍU սu ոn ռn ցg հh զq գq յj աw ԼL Յ3');
// Coptic (Greek-shaped letters)
conf('ⲀA ⲁa ⲂB ⲎH Ⲓl ⲓi ⲔK ⲕk ⲘM ⲚN ⲞO ⲟo ⲢP ⲣp ⲤC ⲥc ⲦT ⲨY ⲩy ⲬX ⲭx');
// Cherokee (capital letters; the small letters are folded to these first, see cherokeeUpper)
conf('ᎠD ᎡR ᎢT Ꭵi Ꭹy ᎪA ᎫJ ᎬE ᎳW ᎷM ᎻH Ꮍy ᏀG Ꮒh ᏃZ Ꮟb ᏔW ᏕS ᏙV ᏚS ᏞL ᏟC ᏢP ᏦK ᏳG ᏴB');
// Lisu (the Fraser alphabet is made of Latin capitals)
conf('ꓮA ꓐB ꓚC ꓓD ꓰE ꓝF ꓖG ꓧH ꓲl ꓙJ ꓗK ꓡL ꓟM ꓠN ꓳO ꓑP ꓣR ꓢS ꓔT ꓴU ꓦV ꓪW ꓫX ꓬY ꓜZ');
// Hebrew, Arabic and other scripts' digits that read as Latin letters
conf('סo וl ןl هo ہo ١l ۱l ٥o ٧v ۷v');
conf('०o ০o ੦o ૦o ୦o ౦o ೦o ൦o ๐o ໐o ၀o ០o ༠o ყy');
// b75r1 (audit G-3): common symbols (Unicode "Common" script, so the script rules in nameRisk never saw
// them) that read as Latin letters — UTS #39 confusables.txt entries for maths, technical, geometric,
// box-drawing and dingbat symbols plus a few Latin-1 signs. A symbol between letters is flagged as well
// (nameRisk 'symbol'), so one missing here can't pass plain either.
conf('∣l ❘l ⏐l │l ┃l ╎l ╏l ¦l ∤l ǁll ⎸l ⎹l');
conf('×x ✕x ✖x ╳x ⨯x ☓x ⤫x ⤬x ⨉x');
conf('⍺a ⍶a ∝a ⍳i ⍸i ℩i ⍴p ⍵w ⍹w ⍷e ℮e ∊e ∈e ⋴e ⋲e ∁c ⊂c ⊏c ∪u ⊍u ⋃u ∨v ⋁v ∩n ⋂n ⊤T ⟙T');
conf('○o ◯o ⚪o ⚬o ❍o ⭘o ◌o ⊚o ∘o ⦾o ⦿o ⵔo ⊖o ⊘o ⌀o ⍉o');
conf('¡i ¢c ¥Y €e ƒf');

/** Cherokee small letters (U+AB70–ABBF, U+13F8–13FD) -> their capitals (U+13A0–13EF, U+13F0–13F5) */
function cherokeeUpper(cp: number): number {
  if (cp >= 0xab70 && cp <= 0xabbf) return cp - 0xab70 + 0x13a0;
  if (cp >= 0x13f8 && cp <= 0x13fd) return cp - 8;
  return cp;
}

function fold(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = String.fromCodePoint(cherokeeUpper(ch.codePointAt(0)!));
    out += CONFUSABLE[c] ?? c;
  }
  return out;
}

/**
 * The comparison key for a name (b75, audit GR-4): invisible characters removed,
 * compatibility forms folded (NFKC), EVERY combining mark dropped (b71 dropped only
 * U+0300–036F, so a Cyrillic titlo or any other script's mark made a copy look new),
 * look-alike letters folded to one Latin form (CONFUSABLE, before and after
 * lower-casing), and "rn" / "vv" read as "m" / "w".
 */
export function nameSkeleton(n: string): string {
  const s = stripInvisible(n).normalize('NFKC').replace(checkRun(), '').normalize('NFD').replace(MARKS, ''); // b77u (L-12)
  return fold(fold(s).toLowerCase())
    .replace(/rn/g, 'm').replace(/vv/g, 'w')
    .replace(/\s+/g, ' ').trim();
}

/**
 * b75 (audit GR-4): a name as other members see it — cleaned (cleanName), NFKC, and every
 * character that can pass for the app's own " · <ID>" separator replaced with '-' (only
 * the app adds that mark). SEPARATOR_LOOKALIKES is every dot, bullet, word separator and
 * full stop Unicode names, plus the middle-dot shapes (b70 kept a hand list of 22; U+A78F,
 * U+10101 and U+0701 got through it).
 */
export function displayGroupName(n: string): string {
  return cleanName(n).normalize('NFKC').replace(SEPARATOR_LOOKALIKES, '-');
}

/** b75 (audit GR-4): words a member's chosen name may not use to look like a role the app shows */
const RESERVED_WORDS = new Set(['creator', 'founder', 'admin', 'administrator', 'owner', 'moderator', 'mod', 'vardum', 'system', 'official']);

type Script = 'Latn' | 'Grek' | 'Cyrl' | 'Armn' | 'Hebr' | 'Arab' | 'Geor' | 'Thaa' | 'Deva' | 'Beng' | 'Guru' | 'Gujr' | 'Orya'
  | 'Taml' | 'Telu' | 'Knda' | 'Mlym' | 'Sinh' | 'Thai' | 'Laoo' | 'Tibt' | 'Mymr' | 'Ethi' | 'Khmr' | 'Hang' | 'Hira' | 'Kana'
  | 'Bopo' | 'Hani' | 'Zyyy' | 'Other';

/**
 * The scripts UTS #31 Table 5 recommends for identifiers (the ones people's names are written
 * in), by block — a compact approximation of the Unicode Script property (no property escapes:
 * see the header). Anything not listed and not common punctuation, symbols or emoji is 'Other':
 * Excluded and Limited Use scripts such as Cherokee, Lisu, Coptic, Syriac, Canadian syllabics,
 * Old Italic or Aegean.
 */
const SCRIPT_RANGES: Array<[number, number, Script]> = [
  [0x41, 0x5a, 'Latn'], [0x61, 0x7a, 'Latn'], [0xaa, 0xaa, 'Latn'], [0xba, 0xba, 'Latn'], [0xc0, 0xd6, 'Latn'], [0xd8, 0xf6, 'Latn'],
  [0xf8, 0x2b8, 'Latn'], [0x2e0, 0x2e4, 'Latn'], [0x1d00, 0x1d25, 'Latn'], [0x1d2c, 0x1d5c, 'Latn'], [0x1d62, 0x1d65, 'Latn'],
  [0x1d6b, 0x1d77, 'Latn'], [0x1d79, 0x1dbe, 'Latn'], [0x1e00, 0x1eff, 'Latn'], [0x2c60, 0x2c7f, 'Latn'], [0xa722, 0xa787, 'Latn'],
  [0xa78b, 0xa7ff, 'Latn'], [0xab30, 0xab5a, 'Latn'], [0xab5c, 0xab64, 'Latn'], [0xab66, 0xab69, 'Latn'], [0xfb00, 0xfb06, 'Latn'],
  [0xff21, 0xff3a, 'Latn'], [0xff41, 0xff5a, 'Latn'], [0x10780, 0x107ba, 'Latn'], [0x1df00, 0x1df2a, 'Latn'],
  [0x370, 0x373, 'Grek'], [0x375, 0x377, 'Grek'], [0x37a, 0x37d, 'Grek'], [0x37f, 0x37f, 'Grek'], [0x384, 0x384, 'Grek'],
  [0x386, 0x386, 'Grek'], [0x388, 0x3e1, 'Grek'], [0x3f0, 0x3ff, 'Grek'], [0x1d26, 0x1d2a, 'Grek'], [0x1d5d, 0x1d61, 'Grek'],
  [0x1d66, 0x1d6a, 'Grek'], [0x1dbf, 0x1dbf, 'Grek'], [0x1f00, 0x1ffe, 'Grek'], [0xab65, 0xab65, 'Grek'],
  [0x400, 0x52f, 'Cyrl'], [0x1c80, 0x1c88, 'Cyrl'], [0x1d2b, 0x1d2b, 'Cyrl'], [0x1d78, 0x1d78, 'Cyrl'], [0x2de0, 0x2dff, 'Cyrl'],
  [0xa640, 0xa69f, 'Cyrl'], [0x1e030, 0x1e08f, 'Cyrl'],
  [0x531, 0x556, 'Armn'], [0x559, 0x588, 'Armn'], [0x58a, 0x58f, 'Armn'], [0xfb13, 0xfb17, 'Armn'],
  [0x591, 0x5f4, 'Hebr'], [0xfb1d, 0xfb4f, 'Hebr'],
  [0x600, 0x604, 'Arab'], [0x606, 0x60b, 'Arab'], [0x60d, 0x61a, 'Arab'], [0x61c, 0x61e, 'Arab'], [0x620, 0x63f, 'Arab'],
  [0x641, 0x6dc, 'Arab'], [0x6de, 0x6ff, 'Arab'], [0x750, 0x77f, 'Arab'], [0x870, 0x8ff, 'Arab'], [0xfb50, 0xfdff, 'Arab'],
  [0xfe70, 0xfefc, 'Arab'], [0x10e60, 0x10e7e, 'Arab'], [0x1ee00, 0x1eeff, 'Arab'],
  [0x10a0, 0x10fa, 'Geor'], [0x10fc, 0x10ff, 'Geor'], [0x1c90, 0x1cbf, 'Geor'], [0x2d00, 0x2d2f, 'Geor'],
  [0x780, 0x7bf, 'Thaa'], [0x900, 0x963, 'Deva'], [0x966, 0x97f, 'Deva'], [0xa8e0, 0xa8ff, 'Deva'], [0x980, 0x9ff, 'Beng'],
  [0xa00, 0xa7f, 'Guru'], [0xa80, 0xaff, 'Gujr'], [0xb00, 0xb7f, 'Orya'], [0xb80, 0xbff, 'Taml'], [0x11fc0, 0x11fff, 'Taml'],
  [0xc00, 0xc7f, 'Telu'], [0xc80, 0xcff, 'Knda'], [0xd00, 0xd7f, 'Mlym'], [0xd80, 0xdff, 'Sinh'], [0xe01, 0xe3a, 'Thai'],
  [0xe40, 0xe5b, 'Thai'], [0xe80, 0xeff, 'Laoo'], [0xf00, 0xfd4, 'Tibt'], [0xfd9, 0xfff, 'Tibt'], [0x1000, 0x109f, 'Mymr'],
  [0xa9e0, 0xa9ff, 'Mymr'], [0xaa60, 0xaa7f, 'Mymr'], [0x1200, 0x139f, 'Ethi'], [0x2d80, 0x2ddf, 'Ethi'], [0xab00, 0xab2f, 'Ethi'],
  [0x1780, 0x17ff, 'Khmr'], [0x19e0, 0x19ff, 'Khmr'],
  [0x1100, 0x11ff, 'Hang'], [0x3131, 0x318e, 'Hang'], [0xa960, 0xa97f, 'Hang'], [0xac00, 0xd7ff, 'Hang'], [0xffa0, 0xffdc, 'Hang'],
  [0x3041, 0x309f, 'Hira'], [0x1b001, 0x1b11f, 'Hira'], [0x30a1, 0x30fa, 'Kana'], [0x30fd, 0x30ff, 'Kana'], [0x31f0, 0x31ff, 'Kana'],
  [0x32d0, 0x32fe, 'Kana'], [0x3300, 0x3357, 'Kana'], [0xff66, 0xff6f, 'Kana'], [0xff71, 0xff9d, 'Kana'], [0x1aff0, 0x1b000, 'Kana'],
  [0x3105, 0x312f, 'Bopo'], [0x31a0, 0x31bf, 'Bopo'],
  [0x2e80, 0x2fdf, 'Hani'], [0x3005, 0x3005, 'Hani'], [0x3007, 0x3007, 'Hani'], [0x3021, 0x3029, 'Hani'], [0x3038, 0x303b, 'Hani'],
  [0x3400, 0x4dbf, 'Hani'], [0x4e00, 0x9fff, 'Hani'], [0xf900, 0xfaff, 'Hani'], [0x20000, 0x323af, 'Hani'],
  // common: ASCII and Latin-1 punctuation/symbols/digits, modifier symbols, general punctuation through
  // the misc symbols and arrows, CJK punctuation, small and full-width forms, emoji
  [0x0, 0x40, 'Zyyy'], [0x5b, 0x60, 'Zyyy'], [0x7b, 0xbf, 'Zyyy'], [0xd7, 0xd7, 'Zyyy'], [0xf7, 0xf7, 'Zyyy'], [0x2b9, 0x2df, 'Zyyy'],
  [0x2e5, 0x2ff, 'Zyyy'], [0x2000, 0x2bff, 'Zyyy'], [0x2e00, 0x2e7f, 'Zyyy'], [0x3000, 0x303f, 'Zyyy'], [0x30fb, 0x30fc, 'Zyyy'],
  [0xfe10, 0xfe6f, 'Zyyy'], [0xff00, 0xff20, 'Zyyy'], [0xff3b, 0xff40, 'Zyyy'], [0xff5b, 0xff65, 'Zyyy'], [0xff70, 0xff70, 'Zyyy'],
  [0xffe0, 0xffee, 'Zyyy'], [0x1f000, 0x1fbff, 'Zyyy'],
];

function scriptOf(cp: number): Script {
  // first match wins (the specific script ranges come before the common ones)
  for (const [a, b, s] of SCRIPT_RANGES) if (cp >= a && cp <= b) return s;
  return 'Other';
}

/** b75r1 (audit G-3): Common-script symbols that can stand in for a letter — Latin-1 signs (not ª º or the
 *  soft hyphen), currency, letterlike symbols, number forms, arrows, maths operators, technical, control
 *  pictures, enclosed alphanumerics, box drawing, blocks, geometric shapes, misc symbols, dingbats,
 *  supplemental arrows and maths, misc symbols and arrows, and the half-width symbol forms. General
 *  punctuation (U+2000–206F: ’ ‐ and the like) and emoji (U+1F000 on) are not in it. */
function isLetterlikeSymbol(cp: number): boolean {
  return (cp >= 0xa1 && cp <= 0xbf && cp !== 0xaa && cp !== 0xba && cp !== 0xad) || cp === 0xd7 || cp === 0xf7
    || (cp >= 0x20a0 && cp <= 0x2bff) || (cp >= 0xffe0 && cp <= 0xffee);
}

/** b75r1 (audit G-2): words the app itself writes in a group's notices. A name using them could make a
 *  notice read as another one ("m0 left the group. Dan" joined the group), so it is never shown plain and
 *  can't be chosen on this phone (groupNameProblem). Compared on the skeleton. */
const APP_PHRASES = ['joined the group', 'left the group', 'leaving the group', 'says they are leaving', 'renamed to', 'is now shown as',
  'was removed', 'removed you', 'removed someone', 'removed from the group', 'group keys', 'group key', 'group creator', 'reach this phone', 'safety code'];
let phraseSkeletons: string[] | null = null;
const wordsOf = (sk: string): string => ` ${sk.replace(/[^a-z0-9]+/g, ' ').trim()} `;

/** UTS #39 "highly restrictive": one script, or Latin with the CJK sets that are written together */
const ALLOWED_MIXES: Script[][] = [['Latn', 'Hani', 'Hira', 'Kana'], ['Latn', 'Hani', 'Bopo'], ['Latn', 'Hani', 'Hang']];

/**
 * b75 (audit GR-4): why a name can't be trusted to look unique, or null.
 *  - 'script': a character from a script outside the common set (Cherokee, Lisu, Coptic,
 *    Syriac, …), which is where most look-alikes of Latin letters live;
 *  - 'mixed': letters from more than one script (UTS #39 highly restrictive: Latin may mix
 *    only with Han + Hiragana/Katakana, Han + Bopomofo, or Han + Hangul);
 *  - 'role': it uses a role word the app shows (creator, admin, owner, …), e.g. "Matt (creator)";
 *  - 'id': it contains another member's ID prefix (passed in), so it can pass for the app's label;
 *  - 'symbol' (b75r1, audit G-3): a maths, technical, geometric, box-drawing, dingbat or similar symbol right
 *    next to a letter or digit ("A∣ice", "B○b", "CREAT○R") — Common-script characters, so the script rules
 *    above never saw them, and the skeleton folds only the common ones;
 *  - 'phrase' (b75r1, audit G-2): it uses words the app writes in group notices ("left the group").
 * Such a name is never shown plain: it always carries the app's ID suffix.
 */
export function nameRisk(n: string, otherIdPrefixes: Iterable<string> = []): 'script' | 'mixed' | 'role' | 'id' | 'symbol' | 'phrase' | null {
  if (hasCheckMark(n)) return 'symbol'; // b77u (audit 6 L-12): a check mark anywhere
  const s = stripInvisible(n).normalize('NFKC').normalize('NFD').replace(MARKS, '');
  const scripts = new Set<Script>();
  const cps = [...s].map((ch) => ch.codePointAt(0)!);
  for (const cp of cps) {
    const sc = scriptOf(cp);
    if (sc === 'Other') return 'script';
    if (sc !== 'Zyyy') scripts.add(sc);
  }
  if (scripts.size > 1 && !ALLOWED_MIXES.some((set) => [...scripts].every((x) => set.includes(x)))) return 'mixed';
  // b75r1 (audit G-3): a letter-like symbol touching a letter or digit
  const wordChar = (cp: number | undefined): boolean => cp !== undefined && ((cp >= 0x30 && cp <= 0x39) || scriptOf(cp) !== 'Zyyy');
  for (let i = 0; i < cps.length; i++) if (isLetterlikeSymbol(cps[i]) && (wordChar(cps[i - 1]) || wordChar(cps[i + 1]))) return 'symbol';
  const sk = nameSkeleton(n);
  if (sk.split(/[^a-z0-9]+/).some((w) => RESERVED_WORDS.has(w))) return 'role';
  // b75r1 (audit G-2)
  if (!phraseSkeletons) phraseSkeletons = APP_PHRASES.map((p) => wordsOf(nameSkeleton(p)));
  const words = wordsOf(sk);
  if (phraseSkeletons.some((p) => words.includes(p))) return 'phrase';
  for (const p of otherIdPrefixes) {
    const pk = nameSkeleton(p);
    if (pk.length >= 6 && sk.includes(pk)) return 'id';
  }
  return null;
}

/**
 * b75r1 (audit G-2): why a name typed on THIS phone for use in groups is refused, or null. Other people's
 * names can't be refused here (they arrive signed by their own phones): those are quoted in every notice
 * (noteName) and flagged by nameRisk. Refused: a full stop, ! or ? followed by more words (a name that reads
 * as two sentences — "m0 left the group. Dan"), quote marks (they would end the quotes notices put round
 * names), and the app's own notice words.
 */
export function groupNameProblem(n: string): string | null {
  const c = cleanName(n);
  if (!c) return null;
  if (/[.!?。！？…]\s+\S/u.test(c)) return 'A name can’t have a full stop, ! or ? followed by more words, because it could look like a notice from the app.';
  if (c.replace(QUOTES, '') !== c) return 'A name can’t contain double quote marks.';
  if (hasCheckMark(n)) return 'A name can’t contain a check mark, because it could look like the mark Vardum shows for a verified contact.'; // b77u (L-12)
  if (nameRisk(c) === 'phrase') return 'A name can’t use the words the app writes in group notices (like “left the group”).';
  return null;
}

/** double quote marks and their look-alikes (U+0022, U+201C–201F, U+00AB, U+00BB, U+2033, U+2036, U+275D–275E,
 *  U+301D–301F, U+FF02) — replaced in a name shown in a notice, so it can't close the notice's own quotes */
const QUOTES = /["“-‟«»″‶❝❞〝-〟＂]/gu;

/**
 * b75r1 (audit G-2): a name as it appears inside a group notice — in curly double quotes, isolated (FSI … PDI,
 * so a right-to-left name can't reorder the notice), with any double quote mark of its own shown as ', so
 * whatever a member calls itself reads as one quoted name and never as part of the notice's sentence.
 * (b75 put the name in bare: a member named "m0 left the group. Dan" made every phone show
 * "m0 left the group. Dan joined the group".)
 */
export function noteName(shown: string): string {
  return `“${isolateName(String(shown ?? '').replace(QUOTES, '\''))}”`;
}

/**
 * b77k (IP77-3, owner decision): a 1:1 peer's own nickname (sent inside the chat, chat.ts
 * buildNickIntro) in a chat title. b77k2 (owner decision): the nickname ONLY — no " · ID8" suffix
 * (the phones showed "IOS 2 · FgY9efBV"); the full Vardum ID moves to the row's subtitle. Still
 * cleaned (displayGroupName: separator look-alikes, invisible and bidi controls, the length cap) and
 * isolated. Only ever for a pinned contact whose key matches (the caller's rule): a stranger can't
 * wear a nickname as a title, so a nickname alone can't impersonate a contact. '' = none.
 */
export function peerNickTitle(nick: string | null | undefined, ctx: { veilId?: string | null; others?: Iterable<string> } = {}): string {
  const n = displayGroupName(String(nick ?? ''));
  if (!n) return '';
  // b77k2 (re-review M2): a nickname shaped like a Vardum ID is never a title (it could be another
  // contact's ID, which is that contact's title when I gave them no name)
  if (idShaped(n)) return '';
  // ... and one that clashes with another contact's title, local name or ID (confusable skeleton),
  // or that nameRisk flags (mixed scripts, role words, app phrases, another ID's prefix), keeps the
  // app's ID mark after it, as a group does (uniqueGroupNick). The normal case stays nickname-only.
  const id8 = cleanName(String(ctx.veilId ?? '')).slice(0, 8);
  const others = [...(ctx.others ?? [])].map((o) => cleanName(String(o ?? ''))).filter((o) => !!o);
  const sk = nameSkeleton(n);
  const clash = others.some((o) => nameSkeleton(o) === sk || nameSkeleton(o.slice(0, 8)) === sk);
  const prefixes = others.filter(idShaped).map((o) => o.slice(0, 8));
  if (clash || nameRisk(n, prefixes)) return id8 ? `${isolateName(n)} · ${id8}` : '';
  return isolateName(n);
}

/** b77k2 (re-review M2): looks like a Vardum ID (base58, 12–24 characters, no space, digits and both
 *  cases). Real names that happen to be one long base58 word without digits are not caught. */
export function idShaped(s: string): boolean {
  const t = cleanName(String(s ?? '')).replace(/[⁨⁩]/g, '');
  return /^[1-9A-HJ-NP-Za-km-z]{12,24}$/.test(t) && /[0-9]/.test(t) && /[A-Z]/.test(t) && /[a-z]/.test(t);
}

/** b77k2 (re-review, info): a title's first characters for an avatar, without the isolate marks */
export function titleInitials(title: string, n = 2): string {
  return String(title ?? '').replace(/[⁦-⁩‪-‮‎‏]/g, '').trim().slice(0, n);
}

/**
 * b77k (IP77-3): the same nickname for a chat whose peer this phone can't vouch for (not pinned,
 * a request, an invite chat): never in the title (b71: such a chat never wears the sender's
 * self-chosen name), only quoted in the subtitle — "calls themselves “…”". '' = none.
 */
export function peerNickNote(nick: string | null | undefined): string {
  const n = displayGroupName(String(nick ?? ''));
  return n ? `calls themselves ${noteName(n)}` : '';
}
