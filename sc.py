import ast, io, json, os, re, shlex, subprocess, sys, tempfile
from collections import Counter
import streamlit as st
import matplotlib.pyplot as plt
from fpdf import FPDF

st.set_page_config(page_title="Secure Code Analyzer", page_icon="🛡️", layout="wide")
MAX_FILE_SIZE = 1024 * 1024

# ---------- Premium dark cybersecurity theme ----------
CSS = r'''<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root{--bg:#070b16;--panel:#101827;--panel2:#151f31;--line:#27364d;--blue:#3b82f6;--blue2:#60a5fa;--mint:#14f1c3;--green:#22c55e;--amber:#fbbf24;--red:#f87171;--text:#f1f5fb;--muted:#a5b4c8}
.stApp{background:radial-gradient(ellipse at 15% 0%,#122442 0%,transparent 36%),linear-gradient(145deg,#070b16 0%,#0b1220 52%,#090e19 100%);font-family:Inter,sans-serif;color:var(--text)}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#080e1a,#0b1322 72%,#080e19);border-right:1px solid #24334a}
[data-testid="stSidebar"] *{color:#dce7f5}
.block-container{padding-top:1.35rem;padding-bottom:2.4rem;max-width:1500px}
.brand{padding:12px 8px 20px;margin-bottom:17px;border-bottom:1px solid #26364c}
.brand-row{display:flex;align-items:center;gap:11px}
.brand-mark{width:48px;height:48px;flex:0 0 48px;filter:drop-shadow(0 0 12px #14f1c355)}
.brand-title{font-weight:800;font-size:17px;line-height:1.2;letter-spacing:.3px;color:#f8fbff}.brand-blue{color:#60a5fa}
.brand-tag{font-size:11px;color:#9db0c8;margin-top:7px;letter-spacing:.45px}.brand-ar{font-size:12px;color:#14f1c3;margin-top:4px}
.hero{position:relative;overflow:hidden;background:linear-gradient(115deg,#14253e 0%,#101b2c 60%,#101827 100%);border:1px solid #30445f;border-radius:20px;padding:23px 25px;margin:0 0 20px;box-shadow:0 10px 30px #0002}
.hero:after{content:"";position:absolute;right:-55px;top:-90px;width:230px;height:230px;border-radius:50%;border:1px solid #60a5fa22;box-shadow:0 0 0 24px #60a5fa09,0 0 0 48px #14f1c306;pointer-events:none}
.hero h1{font-size:27px;margin:0;color:#f8fafc;font-weight:800}.hero p{margin:8px 0 0;color:#b7c8dc;font-size:14px}
.card{background:linear-gradient(145deg,#17243a,#111a29);border:1px solid #30415a;border-radius:16px;padding:18px 18px 15px;min-height:115px;box-shadow:0 6px 18px #0002}
.card-label{color:#b1c1d5;font-size:12px;letter-spacing:.4px}.card-value{font-size:30px;font-weight:800;color:#f8fafc;margin-top:7px}.card-note{font-size:12px;color:#91a4bd;margin-top:5px}
.section-title{font-size:18px;font-weight:750;color:#edf5ff;margin:15px 0 10px}
div[data-testid="stMetric"]{background:linear-gradient(145deg,#17243a,#111a29);border:1px solid #30415a;padding:14px 16px;border-radius:14px}
div[data-testid="stMetric"] label{color:#aebfd4!important}div[data-testid="stMetric"] [data-testid="stMetricValue"]{color:#f8fafc!important}
.stButton>button,.stDownloadButton>button{border-radius:11px!important;border:1px solid #3a5272!important;font-weight:650!important;background:#17243a!important;color:#eef6ff!important;transition:.18s!important;min-height:42px}
.stButton>button[kind="primary"]{background:linear-gradient(100deg,#2563eb,#3b82f6)!important;border:1px solid #60a5fa!important;color:white!important;box-shadow:0 5px 18px #2563eb35}
.stButton>button:hover,.stDownloadButton>button:hover{border-color:#14f1c3!important;transform:translateY(-1px);box-shadow:0 5px 18px #14f1c318}
[data-testid="stFileUploader"]{background:#111c2b;border:1px dashed #49617e;border-radius:14px;padding:9px}
[data-testid="stExpander"]{background:#121d2c;border:1px solid #2c3d54;border-radius:13px}
[data-testid="stTabs"] button{color:#b8c8dc}.stAlert{border-radius:12px}
[data-testid="stRadio"] label{font-weight:600}hr{border-color:#27364d!important}.small-muted{color:#94a8c1;font-size:11px;letter-spacing:.35px}
[data-testid="stSidebar"] [role="radiogroup"]{gap:5px}[data-testid="stSidebar"] [role="radio"]{padding:9px 10px;border-radius:10px}
[data-testid="stSidebar"] [role="radio"]:hover{background:#142238}
</style>'''
st.markdown(CSS, unsafe_allow_html=True)

# ---------- State ----------
DEFAULTS = dict(original_code=None, original_name=None, original_findings=None, fixed_code=None,
                fixes=[], warnings=[], fixed_findings=None, comparison=None, scan_error=None,
                safety_results=None, safety_error=None, requirements_name=None, requirements_text=None)
for k,v in DEFAULTS.items():
    if k not in st.session_state: st.session_state[k] = v

def reset_results():
    for k,v in DEFAULTS.items(): st.session_state[k] = v

def safe_text(v): return "" if v is None else str(v)

def ensure_import(code, module):
    try: tree=ast.parse(code)
    except SyntaxError: return code
    for node in tree.body:
        if isinstance(node,ast.Import) and any(a.name==module for a in node.names): return code
        if isinstance(node,ast.ImportFrom) and node.module==module: return code
    lines=code.splitlines(keepends=True); pos=0
    if lines and lines[0].startswith('#!'): pos=1
    if pos<len(lines) and re.match(r'#.*coding[:=]\s*[-\w.]+',lines[pos]): pos+=1
    while pos<len(lines) and (not lines[pos].strip() or lines[pos].lstrip().startswith('#')): pos+=1
    try:
        t=ast.parse(''.join(lines[pos:]))
        if t.body and isinstance(t.body[0],ast.Expr) and isinstance(t.body[0].value,ast.Constant) and isinstance(t.body[0].value.value,str): pos+=t.body[0].end_lineno
    except SyntaxError: pass
    while pos<len(lines) and lines[pos].strip().startswith('from __future__ import '): pos+=1
    lines.insert(pos,f'import {module}\n'); return ''.join(lines)

def auto_fix_code(source):
    fixed=source; fixes=[]; warnings=[]
    pat=re.compile(r'''(?P<func>subprocess\.(?:run|call|Popen|check_call|check_output))\(\s*(?P<quote>['"])(?P<command>[^'"\r\n]*)(?P=quote)\s*,\s*shell\s*=\s*True\s*\)''')
    def sub(m):
        cmd=m.group('command'); dangerous=[';','|','&','>','<','`','$','\n']
        if any(c in cmd for c in dangerous):
            warnings.append('لم يُعدّل أمر subprocess لأنه قد يحتوي على shell operators.'); return m.group(0)
        try:
            argv=shlex.split(cmd,posix=True)
            if not argv:return m.group(0)
            fixes.append('تحويل subprocess إلى قائمة وسائط وتعطيل shell=True.')
            return f"{m.group('func')}({argv!r}, shell=False)"
        except ValueError:
            warnings.append('تعذر تحليل أمر subprocess؛ تُرك دون تعديل.'); return m.group(0)
    fixed=pat.sub(sub,fixed)
    secret=re.compile(r'^(?:PASSWORD|PASS|SECRET|API_KEY|TOKEN|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET)(?:_[A-Z0-9]+)*$',re.I)
    def bytecol_to_char(line,col): return len(line.encode('utf-8')[:col].decode('utf-8',errors='ignore'))
    try:
        tree=ast.parse(fixed); lines=fixed.splitlines(keepends=True); offsets=[]; total=0
        for line in lines: offsets.append(total); total+=len(line)
        repl=[]
        for n in ast.walk(tree):
            val=None; names=[]
            if isinstance(n,ast.Assign):
                val=n.value
                if len(n.targets)==1 and isinstance(n.targets[0],ast.Name): names=[n.targets[0].id]
            elif isinstance(n,ast.AnnAssign):
                val=n.value
                if isinstance(n.target,ast.Name): names=[n.target.id]
            if not val or not isinstance(val,ast.Constant) or not isinstance(val.value,str) or not val.value or not names:continue
            name=names[0]
            if not secret.match(name):continue
            sl=val.lineno-1; el=val.end_lineno-1
            sc=bytecol_to_char(lines[sl],val.col_offset); ec=bytecol_to_char(lines[el],val.end_col_offset)
            start=offsets[sl]+sc; end=offsets[el]+ec
            repl.append((start,end,f'os.getenv("{name.upper()}")',name))
        for a,b,replacement,name in sorted(repl,reverse=True):
            fixed=fixed[:a]+replacement+fixed[b:]; fixes.append(f'استبدال قيمة {name} الثابتة بمتغير بيئة.')
        if repl:
            fixed=ensure_import(fixed,'os'); vars=sorted({x[3].upper() for x in repl})
            warnings.append('يجب ضبط متغيرات البيئة التالية؛ وإلا قد تكون قيمتها None: '+', '.join(vars))
    except SyntaxError: warnings.append('تعذر تحليل الكود نحوياً؛ لم تُجر معالجة للأسرار.')
    try:
        t=ast.parse(fixed)
        if any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='eval' for n in ast.walk(t)):
            warnings.append('استخدام eval() يحتاج مراجعة مصدر المدخلات. لم يُعدّل تلقائياً.')
        has_sql=False; has_execute=False
        for n in ast.walk(t):
            if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add):
                seg=ast.get_source_segment(fixed,n)
                if seg and 'SELECT' in seg.upper(): has_sql=True
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='execute':has_execute=True
        if has_sql and has_execute:warnings.append('قد يوجد SQL Injection بسبب بناء SQL بدمج النصوص؛ استخدم Parameterized Queries.')
    except SyntaxError: warnings.append('تعذر تحليل الكود بعد محاولة التصحيح للكشف عن eval/SQL.')
    return fixed,fixes,warnings

def run_bandit(code):
    path=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',suffix='.py',encoding='utf-8',delete=False) as f:f.write(code);path=f.name
        r=subprocess.run([sys.executable,'-m','bandit','-f','json','-q',path],capture_output=True,text=True,timeout=60)
        if r.returncode not in (0,1):raise RuntimeError(r.stderr.strip() or r.stdout.strip() or 'Bandit failed')
        if not r.stdout.strip():raise RuntimeError('Bandit لم يرجع JSON.')
        return json.loads(r.stdout).get('results',[])
    except subprocess.TimeoutExpired:raise RuntimeError('انتهت مهلة Bandit (60 ثانية).')
    except FileNotFoundError:raise RuntimeError('Bandit غير مثبت في Python الحالي. ثبته عبر python -m pip install bandit')
    except json.JSONDecodeError:raise RuntimeError('تعذر قراءة JSON من Bandit.')
    finally:
        if path and os.path.exists(path):os.remove(path)

def run_safety(requirements):
    path=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',suffix='.txt',encoding='utf-8',delete=False) as f:f.write(requirements);path=f.name
        r=subprocess.run([sys.executable,'-m','safety','check','--file',path,'--json'],capture_output=True,text=True,timeout=90)
        out=r.stdout.strip()
        if not out:return None,r.stderr.strip() or 'Safety لم يرجع بيانات.'
        try:data=json.loads(out)
        except json.JSONDecodeError:
            decoder=json.JSONDecoder(); candidates=[p for p in (out.find('{'),out.find('[')) if p>=0]
            if not candidates:return None,'مخرجات Safety ليست JSON قابلاً للتحليل.'
            try:data,_=decoder.raw_decode(out[min(candidates):])
            except json.JSONDecodeError:return None,'تعذر تحليل مخرجات Safety.'
        if r.returncode not in (0,1):return None,f'Safety exit code {r.returncode}: {r.stderr.strip()}'
        if isinstance(data,list):v=data
        elif isinstance(data,dict):
            v=next((data[k] for k in ('vulnerabilities','report','issues') if isinstance(data.get(k),list)),None)
            if v is None:return None,'بنية نتائج Safety غير معروفة؛ لم نعتبر الفحص سليماً.'
        else:return None,'صيغة نتائج Safety غير متوقعة.'
        return v,None
    except subprocess.TimeoutExpired:return None,'انتهت مهلة فحص Safety.'
    except FileNotFoundError:return None,'Safety غير مثبت. ثبته عبر python -m pip install safety'
    finally:
        if path and os.path.exists(path):os.remove(path)

def stats(code,findings):
    c=Counter(safe_text(x.get('issue_severity','UNKNOWN')).upper() for x in findings)
    return dict(lines=len(code.splitlines()),total=len(findings),high=c['HIGH'],medium=c['MEDIUM'],low=c['LOW'],undefined=c['UNDEFINED'])

def severity_chart(findings):
    s=stats('',findings); fig,ax=plt.subplots(figsize=(6,3.5)); bars=ax.bar(['High','Medium','Low'],[s['high'],s['medium'],s['low']],color=['#f87171','#fbbf24','#14f1c3'],width=.55)
    ax.set_title('Findings by Severity',color='#eef6ff',fontweight='bold');ax.set_ylabel('Count',color='#b9c9dd');ax.set_ylim(bottom=0);ax.set_facecolor('#101827');fig.patch.set_facecolor('#101827');ax.tick_params(colors='#cbd5e1');ax.spines[:].set_color('#2a3b53')
    for b in bars:ax.text(b.get_x()+b.get_width()/2,b.get_height(),str(int(b.get_height())),ha='center',va='bottom',color='#eef6ff',fontweight='bold')
    fig.tight_layout();buf=io.BytesIO();fig.savefig(buf,format='png',dpi=150,facecolor=fig.get_facecolor());buf.seek(0);plt.close(fig);return buf

def compare(old,new):
    norm=lambda x:re.sub(r'\s+',' ',safe_text(x)).strip()
    key=lambda x:(norm(x.get('test_id','')).upper(),norm(x.get('issue_text','')).casefold())
    new_used=[False]*len(new); old_left=[]; remaining=[]
    for a in old:
        ix=next((i for i,b in enumerate(new) if not new_used[i] and key(a)==key(b)),None)
        if ix is None:old_left.append(a)
        else:new_used[ix]=True;remaining.append(a)
    new_left=[b for i,b in enumerate(new) if not new_used[i]]
    def trans(x,id):
        t=norm(x.get('test_id','')).upper(); txt=(norm(x.get('issue_text',''))+' '+norm(x.get('code',''))).lower()
        return t==id and 'subprocess' in txt and ('shell' in txt or 'subprocess' in norm(x.get('issue_text','')).lower())
    old_used=[False]*len(old_left); new_used2=[False]*len(new_left); changed=[]
    for i,a in enumerate(old_left):
        if not trans(a,'B602'):continue
        j=next((j for j,b in enumerate(new_left) if not new_used2[j] and trans(b,'B603')),None)
        if j is not None:old_used[i]=True;new_used2[j]=True;changed.append({'before':a,'after':new_left[j],'reason':'Bandit B602 تغير إلى B603 بعد تعطيل shell=True.'})
    resolved=[a for i,a in enumerate(old_left) if not old_used[i]]; added=[b for i,b in enumerate(new_left) if not new_used2[i]]
    severity=[]; pairs=[{'before':a,'after':next(b for b in new if key(a)==key(b))} for a in remaining];pairs+=changed
    for p in pairs:
        a=p['before'];b=p['after'];s1=norm(a.get('issue_severity','')).upper();s2=norm(b.get('issue_severity','')).upper()
        if s1!=s2:severity.append({'test_id':a.get('test_id'),'before':s1,'after':s2})
    return dict(resolved=len(resolved),new=len(added),remaining=len(remaining),changed=len(changed),resolved_items=resolved,new_items=added,remaining_items=remaining,changed_items=changed,severity_changes=severity,before_total=len(old),after_total=len(new))

def show_findings(findings):
    if not findings:st.success('لم يسجل Bandit مشكلات في هذا الفحص.');return
    for i,x in enumerate(findings,1):
        sev=safe_text(x.get('issue_severity','?')).upper(); conf=safe_text(x.get('issue_confidence','?')).upper(); title=f"{i}. {x.get('test_id','')} · {sev} · Confidence {conf}"
        with st.expander(title):
            st.markdown(f"**الوصف:** {x.get('issue_text','')}")
            st.caption(f"File: {x.get('filename','')} · Line: {x.get('line_number','')}")
            if x.get('code'):st.code(x['code'],language='python')

def pdf_report():
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
    except ImportError:raise RuntimeError('لتقرير العربية ثبّت: python -m pip install arabic-reshaper python-bidi')
    pdf=FPDF();pdf.set_auto_page_break(auto=True,margin=15);pdf.add_page()
    regular=r'C:\Windows\Fonts\arial.ttf';bold=r'C:\Windows\Fonts\arialbd.ttf'
    if not os.path.exists(regular):raise RuntimeError('خط Arial غير متوفر في Windows Fonts.')
    pdf.add_font('Ar','',''+regular);pdf.add_font('Ar','B',bold if os.path.exists(bold) else regular)
    # Explicit usable width avoids FPDF's narrow-cell issue with shaped Arabic text.
    width=pdf.w-pdf.l_margin-pdf.r_margin
    def ar(t,b=False,size=10):
        pdf.set_font('Ar','B' if b else '',size);pdf.set_x(pdf.l_margin)
        shaped=get_display(arabic_reshaper.reshape(safe_text(t)))
        pdf.multi_cell(width,7,shaped,align='R')
    def en(t,b=False,size=10):
        pdf.set_font('Arial','B' if b else '',size);pdf.set_x(pdf.l_margin)
        pdf.multi_cell(width,6,safe_text(t),align='L')
    en('Secure Code Analyzer - Static Security Analysis Report',True,15);ar('تقرير التحليل الأمني الساكن',True,14);en('File: '+safe_text(st.session_state.original_name))
    sections=[('الفحص الأول','Initial Scan',st.session_state.original_findings),('الفحص الثاني','Rescan',st.session_state.fixed_findings)]
    for title,eng,findings in sections:
        ar(title,True,12);en(eng,True,11);ar(f'إجمالي النتائج: {len(findings or [])}')
        for f in findings or []:en(f"{f.get('test_id','')} | {f.get('issue_severity','')} | {f.get('issue_text','')}")
    ar('التصحيحات التلقائية',True,12)
    for f in st.session_state.fixes:ar('• '+f)
    if not st.session_state.fixes:ar('لم تُطبق تصحيحات تلقائية.')
    ar('تنبيهات المراجعة اليدوية',True,12)
    for w in st.session_state.warnings:ar('• '+w)
    if not st.session_state.warnings:ar('لا توجد تنبيهات مراجعة يدوية مسجلة.')
    c=st.session_state.comparison or {};ar('مقارنة الفحصين',True,12)
    for label,key in [('اختفت','resolved'),('جديدة','new'),('متبقية','remaining'),('تغير تصنيفها','changed')]:ar(f'{label}: {c.get(key,0)}')
    ar('فحص الاعتماديات',True,12)
    if st.session_state.safety_error:ar('خطأ Safety: '+st.session_state.safety_error)
    elif st.session_state.safety_results is not None:ar('عدد نتائج المكتبات: '+str(len(st.session_state.safety_results)))
    else:ar('لم يتم فحص الاعتماديات.')
    output=pdf.output();return bytes(output) if isinstance(output,(bytes,bytearray)) else output.encode('latin-1')

# ---------- Inline brand / sidebar navigation ----------
LOGO = '''<svg class="brand-mark" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="sg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#60a5fa"/><stop offset="1" stop-color="#14f1c3"/></linearGradient></defs><path d="M32 4 53 12v17c0 14-9 24-21 31C20 53 11 43 11 29V12L32 4Z" fill="#101f34" stroke="url(#sg)" stroke-width="3"/><path d="M22 32 29 39 43 24" fill="none" stroke="#14f1c3" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/><path d="M32 9 48 15v14c0 10-6 18-16 25" fill="none" stroke="#60a5fa" stroke-width="1.5" opacity=".45"/></svg>'''
with st.sidebar:
    st.markdown(f'<div class="brand"><div class="brand-row">{LOGO}<div><div class="brand-title">SECURE CODE<br><span class="brand-blue">ANALYZER</span></div><div class="brand-tag">ANALYZE · FIX · VERIFY</div></div></div><div class="brand-ar">محلل الكود الأمني · Static Analysis</div></div>',unsafe_allow_html=True)
    page=st.radio('NAVIGATION / التنقل',['Dashboard / لوحة التحكم','Scanner / الفحص','Findings / الثغرات','Remediation / التصحيح','Dependencies / المكتبات','Reports / التقارير'],label_visibility='collapsed')
    st.markdown('<div class="small-muted">STATIC SECURITY ANALYSIS · PYTHON</div>',unsafe_allow_html=True)

# ---------- Dashboard ----------
if page.startswith('Dashboard'):
    st.markdown('<div class="hero"><h1>Security Overview</h1><p>لوحة ملخص التحليل الأمني · Analyze, fix and verify your Python code.</p></div>',unsafe_allow_html=True)
    if st.session_state.original_findings is None:
        st.info('ابدئي من صفحة Scanner برفع ملف Python وتنفيذ الفحص.')
        a,b,c=st.columns(3)
        for col,label,val,note in [(a,'STATIC ANALYSIS','Bandit','Source-code scanning'),(b,'AUTO REMEDIATION','Enabled','Selected patterns only'),(c,'DEPENDENCY SCAN','Safety','requirements.txt')]:
            col.markdown(f'<div class="card"><div class="card-label">{label}</div><div class="card-value">{val}</div><div class="card-note">{note}</div></div>',unsafe_allow_html=True)
        st.markdown('<div class="section-title">Workflow / آلية العمل</div>',unsafe_allow_html=True)
        st.markdown('**01** Upload source  →  **02** Scan  →  **03** Review fixes  →  **04** Verify  →  **05** Export report')
    else:
        s=stats(st.session_state.original_code,st.session_state.original_findings);c=st.session_state.comparison
        cols=st.columns(4);vals=[('TOTAL FINDINGS',s['total'],'Original scan'),('HIGH SEVERITY',s['high'],'Critical attention'),('AUTO FIXES',len(st.session_state.fixes),'Applied patterns'),('RESOLVED',c['resolved'],'After remediation')]
        for col,(label,val,note) in zip(cols,vals):col.markdown(f'<div class="card"><div class="card-label">{label}</div><div class="card-value">{val}</div><div class="card-note">{note}</div></div>',unsafe_allow_html=True)
        st.markdown('<div class="section-title">Severity Distribution / توزيع الخطورة</div>',unsafe_allow_html=True)
        col1,col2=st.columns([1.25,1])
        with col1:st.image(severity_chart(st.session_state.original_findings),use_container_width=True)
        with col2:
            st.markdown('<div class="section-title">Scan Comparison</div>',unsafe_allow_html=True)
            for label,key in [('Resolved','resolved'),('New','new'),('Remaining','remaining'),('Reclassified','changed')]:st.metric(label,c[key])
        st.caption(f"Last file analyzed: {st.session_state.original_name} · {s['lines']} lines")

# ---------- Scanner ----------
elif page.startswith('Scanner'):
    st.markdown('<div class="hero"><h1>Code Scanner</h1><p>Upload a Python file, scan with Bandit and apply limited automatic fixes.</p></div>',unsafe_allow_html=True)
    upload=st.file_uploader('Upload Python source / ارفع ملف Python',type=['py'],key='code_upload')
    if upload:
        if upload.size>MAX_FILE_SIZE:st.error('الحد الأقصى 1 MB.')
        else:
            try:code=upload.getvalue().decode('utf-8');st.success(f'Uploaded: {upload.name}')
            except UnicodeDecodeError:st.error('الملف يجب أن يكون بترميز UTF-8.');code=None
            if code:
                with st.expander('Preview source code / معاينة'):st.code(code,language='python')
                if st.button('🔍 Run Security Analysis / ابدأ الفحص',type='primary',use_container_width=True):
                    reset_results();st.session_state.original_code=code;st.session_state.original_name=upload.name
                    with st.spinner('Running initial scan, auto-fix and rescan…'):
                        try:
                            old=run_bandit(code);fixed,fixes,warnings=auto_fix_code(code)
                            try:ast.parse(fixed)
                            except SyntaxError as e:fixed=code;fixes=[];warnings.append('ألغيت التعديلات بسبب خطأ نحوي: '+str(e))
                            new=run_bandit(fixed);c=compare(old,new)
                            st.session_state.original_findings=old;st.session_state.fixed_code=fixed;st.session_state.fixes=fixes;st.session_state.warnings=warnings;st.session_state.fixed_findings=new;st.session_state.comparison=c
                        except Exception as e:st.session_state.scan_error=str(e)
                    if st.session_state.scan_error:st.error(st.session_state.scan_error)
                    else:st.success('اكتمل الفحص الأول ومحاولة التصحيح وإعادة الفحص. انتقلي إلى Dashboard أو Findings لرؤية النتائج.')
    if st.session_state.original_findings is not None:st.info(f"Current analysis: {st.session_state.original_name}. Use the other navigation pages to inspect saved results.")

# ---------- Findings ----------
elif page.startswith('Findings'):
    st.markdown('<div class="hero"><h1>Security Findings</h1><p>Detected issues, severity and confidence details.</p></div>',unsafe_allow_html=True)
    if st.session_state.original_findings is None:st.info('نفّذي الفحص أولاً من صفحة Scanner.')
    else:
        st.markdown('### Initial scan / الفحص الأول');show_findings(st.session_state.original_findings)
        st.markdown('### Rescan / الفحص الثاني');show_findings(st.session_state.fixed_findings)
        st.markdown('### Severity chart / الرسم');st.image(severity_chart(st.session_state.original_findings),use_container_width=True)

# ---------- Remediation ----------
elif page.startswith('Remediation'):
    st.markdown('<div class="hero"><h1>Remediation Center</h1><p>Review automatic changes and warnings. Always validate fixes manually.</p></div>',unsafe_allow_html=True)
    if st.session_state.original_findings is None:st.info('نفّذي الفحص أولاً من Scanner.')
    else:
        st.markdown('### Applied fixes / التصحيحات')
        if st.session_state.fixes:
            for x in st.session_state.fixes:st.success('✓ '+x)
        else:st.info('لم تُطبق تصحيحات تلقائية.')
        st.markdown('### Manual review / تنبيهات')
        for x in st.session_state.warnings:st.warning(x)
        left,right=st.columns(2)
        with left:st.markdown('#### Before / قبل');st.code(st.session_state.original_code,language='python')
        with right:st.markdown('#### After / بعد');st.code(st.session_state.fixed_code,language='python')
        st.download_button('⬇ Download corrected Python / تحميل الكود المصحح',st.session_state.fixed_code.encode('utf-8'),file_name='fixed_'+st.session_state.original_name,mime='text/x-python',use_container_width=True)
        st.markdown('### Comparison / المقارنة');c=st.session_state.comparison;cols=st.columns(4)
        for col,(label,key) in zip(cols,[('Resolved','resolved'),('New','new'),('Remaining','remaining'),('Reclassified','changed')]):col.metric(label,c[key])
        if c['changed_items']:
            st.markdown('#### Reclassified findings')
            for p in c['changed_items']:
                with st.expander(p['reason']):st.write('Before',p['before'].get('issue_text'));st.code(p['before'].get('code',''));st.write('After',p['after'].get('issue_text'));st.code(p['after'].get('code',''))
        if c['severity_changes']:st.write('Severity changes:',c['severity_changes'])

# ---------- Dependencies ----------
elif page.startswith('Dependencies'):
    st.markdown('<div class="hero"><h1>Dependency Security</h1><p>Check requirements.txt with Safety for known package vulnerabilities.</p></div>',unsafe_allow_html=True)
    req=st.file_uploader('Upload requirements.txt / ارفع ملف المتطلبات',type=['txt'],key='req_upload')
    if req:
        if req.size>MAX_FILE_SIZE:st.error('الحد الأقصى 1 MB.')
        else:
            try:req_text=req.getvalue().decode('utf-8');st.success(f'Uploaded: {req.name}')
            except UnicodeDecodeError:st.error('الملف يجب أن يكون UTF-8.');req_text=None
            if req_text:
                with st.expander('Preview requirements'):st.code(req_text)
                if st.button('🔐 Scan dependencies / افحص المكتبات',type='primary',use_container_width=True):
                    with st.spinner('Safety scanning…'):res,err=run_safety(req_text)
                    st.session_state.safety_results=res;st.session_state.safety_error=err;st.session_state.requirements_name=req.name;st.session_state.requirements_text=req_text
    if st.session_state.safety_error:st.error(st.session_state.safety_error)
    elif st.session_state.safety_results is not None:
        res=st.session_state.safety_results;st.metric('Dependency findings',len(res))
        if not res:st.success('لم يُرجع Safety ثغرات في المتطلبات المفحوصة.')
        else:
            st.warning(f'{len(res)} findings require review')
            for i,item in enumerate(res,1):
                with st.expander(f'Dependency finding #{i}'):
                    if isinstance(item,dict):st.json(item)
                    else:st.write(item)

# ---------- Reports ----------
elif page.startswith('Reports'):
    st.markdown('<div class="hero"><h1>Reports & Export</h1><p>Export scan summary, fixes, warnings, comparison and dependency results.</p></div>',unsafe_allow_html=True)
    if st.session_state.original_findings is None:st.info('نفّذي الفحص من Scanner أولاً.')
    else:
        c=st.session_state.comparison;st.markdown('### Scan summary / ملخص الفحص');cols=st.columns(4)
        for col,(label,key) in zip(cols,[('Resolved','resolved'),('New','new'),('Remaining','remaining'),('Reclassified','changed')]):col.metric(label,c[key])
        st.markdown('### PDF report / التقرير النهائي')
        try:
            data=pdf_report();st.download_button('📄 Download PDF report / تحميل تقرير PDF',data,file_name='Security_Analysis_Report.pdf',mime='application/pdf',type='primary',use_container_width=True)
        except Exception as e:st.error('PDF generation error: '+str(e))
        st.markdown('### Scan files')
        st.download_button('Download corrected source',st.session_state.fixed_code.encode('utf-8'),file_name='fixed_'+st.session_state.original_name,mime='text/x-python')
        st.caption('التقرير يعكس نتائج الأدوات فقط؛ ولا يمثل ضمانًا بأن الكود خالٍ من الثغرات.')

st.divider();st.caption('Secure Code Analyzer · Analyze. Fix. Verify. | Static analysis is not a guarantee of security.')
