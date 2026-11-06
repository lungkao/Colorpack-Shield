#!/usr/bin/env python3
"""Build the embeddable versions of the motion graphic from src/motion.html.

    python3 build_embed.py

Writes embed/motion-embed.html (a full page, for an <iframe>) and embed/motion-paste.html (a fragment to paste
into a Joomla article, module or Custom HTML). Both are fully self-contained: the font is inlined, every id and
class is prefixed "cps-" so nothing can collide with the host page, and the font is registered under its own name
so the site's own "ColorPack" font is never overridden.
"""
import base64
import re
from pathlib import Path

root = Path(__file__).resolve().parent
src = (root / "src" / "motion.html").read_text(encoding="utf-8")
fonts = root.parent / "com_colorpack_shield" / "media" / "fonts"


def b64(name: str) -> str:
    return base64.b64encode((fonts / name).read_bytes()).decode()


style = f"""
@font-face{{font-family:CPShieldFont;src:url(data:font/woff2;base64,{b64('ColorPack-Regular.woff2')}) format('woff2');font-weight:400}}
@font-face{{font-family:CPShieldFont;src:url(data:font/woff2;base64,{b64('ColorPack-Bold.woff2')}) format('woff2');font-weight:700}}
#cps-motion{{position:relative;width:100%;max-width:100%;background:#0b2a4d;overflow:hidden;line-height:0;cursor:pointer}}
#cps-motion svg{{display:block;width:100%;height:auto;font-family:CPShieldFont,'Noto Sans Thai',system-ui,sans-serif}}
#cps-motion .cps-th{{font-family:'Noto Sans Thai',CPShieldFont,sans-serif}}
"""

svg = re.search(r"<svg id=\"s\".*?</svg>", src, re.S).group(0)
svg = svg.replace('id="s" ', "")
svg = re.sub(r'\s(?:width|height)="\d+"(?=[^>]*viewBox)', "", svg, count=0) if False else svg
svg = re.sub(r'id="([^"]+)"', r'id="cps-\1"', svg)
svg = re.sub(r"url\(#([^)]+)\)", r"url(#cps-\1)", svg)
svg = re.sub(r'href="#([^"]+)"', r'href="#cps-\1"', svg)
svg = svg.replace('class="th"', 'class="cps-th"').replace("<svg ", '<svg role="img" aria-label="Colorpack Shield: firewall, login protection, file scan and attacker ban" ', 1)

js = re.search(r"<script>(.*)</script>", src, re.S).group(1)
js = js.replace("const NS='http://www.w3.org/2000/svg', $=id=>document.getElementById(id);",
                "const NS='http://www.w3.org/2000/svg', $=id=>document.getElementById('cps-'+id);")
js = js.replace("for(const k in a)e.setAttribute(k,a[k]);", "for(const k in a)e.setAttribute(k,k==='id'?'cps-'+a[k]:a[k]);")
js = js.replace("'#shield'", "'#cps-shield'").replace("class:th?'th':''", "class:th?'cps-th':''")
js = js.replace("class:th?'th':''", "class:th?'cps-th':''")
tail = js.index("const q=new URLSearchParams")
js = js[:tail] + """(function(){
 const box=document.getElementById('cps-motion');let playing=!window.matchMedia('(prefers-reduced-motion: reduce)').matches,visible=true,at=0,last=performance.now();
 render(0);
 function loop(now){const dt=(now-last)/1000;last=now;if(playing&&visible){at=(at+dt)%TOTAL;render(at)}requestAnimationFrame(loop)}
 requestAnimationFrame(function(n){last=n;loop(n)});
 box.addEventListener('click',function(){playing=!playing;if(!playing)render(0)});
 if('IntersectionObserver' in window)new IntersectionObserver(function(e){visible=e[0].isIntersecting}).observe(box);
})();
"""
js = "(function(){" + js.replace("const q=new URLSearchParams", "const q=new URLSearchParams") + "})();"

fragment = f"""<!-- Colorpack Shield motion graphic. Self-contained: no external files. Click to pause. -->
<style>{style}</style>
<div id="cps-motion">{svg}</div>
<script>{js}</script>
"""

page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Colorpack Shield</title>
<style>html,body{{margin:0;background:#0b2a4d}}</style></head><body>
{fragment}</body></html>
"""

out = root / "embed"
out.mkdir(exist_ok=True)
(out / "motion-paste.html").write_text(fragment, encoding="utf-8")
(out / "motion-embed.html").write_text(page, encoding="utf-8")
print({p.name: p.stat().st_size for p in out.iterdir()})
