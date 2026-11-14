from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET
from pypdf import PdfReader
base=Path.cwd(); out=base/'tmp'/'cnn_plan'
with ZipFile(base/'Modular_IoT_Security_Software_Design.odt') as z:
 root=ET.fromstring(z.read('content.xml'))
 ns={'text':'urn:oasis:names:tc:opendocument:xmlns:text:1.0'}
 pars=[''.join(e.itertext()) for e in root.iter() if e.tag in ['{'+ns['text']+'}p','{'+ns['text']+'}h']]
 (out/'design.txt').write_text('\n'.join(pars),encoding='utf-8')
for f in base.glob('*.pdf'):
 d=PdfReader(f).pages
 text='\n'.join(f'\n=== PDF PAGE {i+1} ===\n'+p.extract_text() for i,p in enumerate(d))
 (out/(f.stem+'.txt')).write_text(text,encoding='utf-8')
 print(f.name,len(d),'pages')
print('DESIGN\n'+(out/'design.txt').read_text(encoding='utf-8'))

