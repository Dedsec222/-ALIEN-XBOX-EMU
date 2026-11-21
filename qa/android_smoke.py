"""Run against an installed debug APK on an Android emulator with an English DocumentsUI."""
import base64
import json
import pathlib
import subprocess
import time
import urllib.request
import xml.etree.ElementTree as ET
import re
import websocket

APP = "com.dedsec.alienxbox"
OUT = pathlib.Path("qa-output")
OUT.mkdir(exist_ok=True)
def adb(*args):
    return subprocess.check_output(["adb", *args], text=True).strip()

def wait(fn, seconds=40):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            result = fn()
            if result:
                return result
        except Exception as exc:
            last = exc
        time.sleep(.35)
    try:
        print(adb("shell","dumpsys","window","windows").split("mCurrentFocus=")[-1][:180],flush=True)
        adb("shell","uiautomator","dump","/sdcard/failure.xml")
        tree=ET.fromstring(adb("shell","cat","/sdcard/failure.xml"))
        print([(n.get("text"),n.get("content-desc")) for n in tree.iter("node") if n.get("text") or n.get("content-desc")],flush=True)
    except Exception:
        pass
    raise AssertionError(f"Timed out waiting for {fn}: {last}")

def start():
    adb("shell","am","start","-W","-n",APP+"/.MainActivity")
    pid = wait(lambda: adb("shell","pidof",APP))
    adb("forward","tcp:9222","localabstract:webview_devtools_remote_"+pid)
    def ready_target():
        targets=json.load(urllib.request.urlopen("http://localhost:9222/json",timeout=2))
        return next((t for t in targets if t.get("url")=="https://genesis.invalid/index.html"),None)
    target=wait(ready_target,60)
    return websocket.create_connection(target["webSocketDebuggerUrl"], suppress_origin=True,timeout=20)

adb("shell","settings","put","secure","immersive_mode_confirmations","confirmed")
adb("shell","wm","dismiss-keyguard")
ws = start()
def call(method, **params):
    ws.send(json.dumps({"id":1,"method":method,"params":params}))
    while True:
        response=json.loads(ws.recv())
        if response.get("id")==1:
            if "error" in response: raise AssertionError(response)
            return response["result"]

def js(expr):
    global ws
    try:
        result=call("Runtime.evaluate",expression=expr,returnByValue=True)
    except websocket.WebSocketConnectionClosedException:
        ws=start()
        result=call("Runtime.evaluate",expression=expr,returnByValue=True)
    if "exceptionDetails" in result: raise AssertionError(result["exceptionDetails"])
    return result["result"].get("value")

def click(selector):
    # Drive rail navigation with real Android touch. Activate other controls
    # through their DOM action so scrolling and dialog animations cannot
    # redirect coordinate taps on slow software-rendered runners.
    wait(lambda: js(f"!!document.querySelector({json.dumps(selector)})"),8)
    if not selector.startswith("nav "):
        js(f"document.querySelector({json.dumps(selector)}).click()")
        time.sleep(.2)
        return
    print("Touch",selector,flush=True)
    coord=js(f"""(()=>{{let el=document.querySelector({json.dumps(selector)});el.scrollIntoView({{block:'center'}});let r=el.getBoundingClientRect();return [r.x+r.width/2,r.y+r.height/2]}})()""")
    scale=js("devicePixelRatio * visualViewport.scale")
    adb("shell","input","tap",str(round(coord[0]*scale)),str(round(coord[1]*scale)))
    time.sleep(.45)

def shot(name):
    try:
        png=base64.b64decode(call("Page.captureScreenshot",format="png")["data"])
    except (AssertionError,KeyError):
        png=subprocess.check_output(["adb","exec-out","screencap","-p"],timeout=15)
    assert png.startswith(b"\x89PNG") and len(png)>4096
    (OUT/name).write_bytes(png)

def node_click(label, seconds=18):
    def locate():
        adb("shell","uiautomator","dump","/sdcard/window.xml")
        xml=ET.fromstring(adb("shell","cat","/sdcard/window.xml"))
        for node in xml.iter("node"):
            labels=[node.get(k,"").casefold() for k in ("text","content-desc")]
            names={label.casefold()}
            if "." in label:
                names.add(pathlib.Path(label).stem.casefold())
            if any(v==n or (v.startswith(n) and v[len(n):len(n)+1] in {","," ","\n"}) for v in labels for n in names):
                x,y,u,v=map(int,re.findall(r"\d+",node.get("bounds")))
                adb("shell","input","tap",str((x+u)//2),str((y+v)//2));return True
    wait(locate,seconds)

def select_download(filename):
    time.sleep(1)
    # Wide screens can expose the roots pane permanently. The picker can
    # also reopen the folder selected during the previous import.
    try:
        node_click(filename,3)
        return
    except AssertionError:
        pass
    try:
        node_click("Downloads",3)
    except AssertionError:
        node_click("Show roots")
        node_click("Downloads")
    try:
        node_click(filename,6)
    except AssertionError:
        # List view exposes document display names even for thumbnail-only grid items.
        node_click("List view",5)
        node_click(filename)
    time.sleep(1)

wait(lambda: js("document.querySelector('#engine')?.textContent==='ONLINE'"))
wait(lambda: js("innerWidth>innerHeight && document.querySelector('.hero').getBoundingClientRect().width>100"))
print("Landscape viewport", js("[innerWidth,innerHeight]"), flush=True)
shot("dashboard.png")
for page in ["Library","Performance","Graphics","Controller","Settings","Diagnostics","About","Dashboard"]:
    click("nav [data-page="+page+"]")
    wait(lambda: js("page")==page,8)
click('[data-act="play"]')
click('[data-num="1"]')
wait(lambda:js("document.querySelector('#dialogbody').textContent.includes('Guest breakpoint')"))
shot('execution.png')
click("#closeModal")
click('[data-act="featured"]');click('[data-act="favorite"]')
click("nav [data-page=Settings]")
js("let theme=document.querySelector('[data-pref=theme]');theme.value='violet';theme.dispatchEvent(new Event('change',{bubbles:true}))")
assert js("document.documentElement.dataset.theme==='violet' && prefs.favorites.includes('doors')")
adb("shell","input","keyevent","KEYCODE_HOME")
ws.close()
adb("shell","am","force-stop",APP)
ws=start()
wait(lambda:js("document.documentElement.dataset.theme==='violet'"))
assert js("prefs.favorites.includes('doors')")
click("nav [data-page=Settings]")
js("let t=document.querySelector('[data-pref=theme]');t.value='teal';t.dispatchEvent(new Event('change',{bubbles:true}))")
click("nav [data-page=Library]")
adb("push","app/src/main/assets/doors.exe","/sdcard/Download/Genesis-fixture.exe")
adb("shell","am","broadcast","-a","android.intent.action.MEDIA_SCANNER_SCAN_FILE","-d","file:///sdcard/Download/Genesis-fixture.exe")
click('[data-act="import"]')
select_download("Genesis-fixture.exe")
wait(lambda:js("data.games.length===2"))
click('[data-detail]:not([data-detail=doors])')
click('[data-act=play]')
wait(lambda:js("document.querySelector('#dialogbody').textContent.includes('Guest breakpoint')"))
click('#closeModal')
adb("push","README.md","/sdcard/Download/invalid.txt")
adb("shell","am","broadcast","-a","android.intent.action.MEDIA_SCANNER_SCAN_FILE","-d","file:///sdcard/Download/invalid.txt")
click("nav [data-page=Library]");click('[data-act=import]')
select_download("invalid.txt")
wait(lambda:js("document.querySelector('#dialogbody').textContent.includes('MZ header')"))
click('#closeModal')
click("nav [data-page=Diagnostics]")
assert js("data.logs.length>=3")
click("nav [data-page=Library]")
js("let search=document.querySelector('#search');search.value='fixture';search.dispatchEvent(new Event('input',{bubbles:true}))")
assert js("document.querySelectorAll('#games .tile').length===1")
click('[data-act=view]')
assert js("document.querySelector('#games').classList.contains('list')")
click('[data-detail]:not([data-detail=doors])')
adb("push","app/src/main/assets/portals.webp","/sdcard/Download/Genesis-cover.webp")
adb("shell","am","broadcast","-a","android.intent.action.MEDIA_SCANNER_SCAN_FILE","-d","file:///sdcard/Download/Genesis-cover.webp")
# Images can appear as thumbnail-only tiles in the Downloads provider.
# Use a single distinctly named image in Pictures via the Images root.
click("[data-act=art]")
select_download("Genesis-cover.webp")
wait(lambda:js("game().art>0"))
click("nav [data-page=Controller]")
click('[data-act=bind][data-key=Confirm]')
adb("shell","input","gamepad","keyevent","KEYCODE_BUTTON_X")
wait(lambda:js("prefs.mapping.Confirm==='BUTTON_X'"))
click("nav [data-page=Diagnostics]")
click("[data-act=export]")
time.sleep(1)
node_click("Save")
wait(lambda: js("document.querySelector('#toast').textContent.includes('exported')"))
print("PASS: artwork import, virtual gamepad mapping, report export, search and list view.")
print("PASS: landscape, all destinations, touch, JNI execution, favorites, theme restart, Android document selection, imported execution and invalid-file handling.")
