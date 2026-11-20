"""Run against an installed debug APK on an Android emulator with an English DocumentsUI."""
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
    raise AssertionError(f"Timed out waiting for {fn}: {last}")

def start():
    adb("shell","am","start","-n",APP+"/.MainActivity")
    pid = wait(lambda: adb("shell","pidof",APP))
    adb("forward","tcp:9222","localabstract:webview_devtools_remote_"+pid)
    targets = wait(lambda: json.load(urllib.request.urlopen("http://localhost:9222/json",timeout=2)))
    return websocket.create_connection(targets[0]["webSocketDebuggerUrl"], suppress_origin=True,timeout=10)

ws = start()
def call(method, **params):
    ws.send(json.dumps({"id":1,"method":method,"params":params}))
    while True:
        response=json.loads(ws.recv())
        if response.get("id")==1:
            if "error" in response: raise AssertionError(response)
            return response["result"]

def js(expr):
    result=call("Runtime.evaluate",expression=expr,returnByValue=True)
    if "exceptionDetails" in result: raise AssertionError(result["exceptionDetails"])
    return result["result"].get("value")

def click(selector):
    coord=js(f"""(()=>{{let el=document.querySelector({json.dumps(selector)});el.scrollIntoView({{block:'center'}});let r=el.getBoundingClientRect();return [r.x+r.width/2,r.y+r.height/2]}})()""")
    call("Input.dispatchTouchEvent",type="touchStart",touchPoints=[{"x":coord[0],"y":coord[1]}])
    call("Input.dispatchTouchEvent",type="touchEnd",touchPoints=[])
    time.sleep(.2)

def shot(name):
    (OUT/name).write_bytes(subprocess.check_output(["adb","exec-out","screencap","-p"]))

def node_click(label):
    def locate():
        adb("shell","uiautomator","dump","/sdcard/window.xml")
        xml=ET.fromstring(adb("shell","cat","/sdcard/window.xml"))
        for node in xml.iter("node"):
            if node.get("text","").lower()==label.lower() or node.get("content-desc","").lower()==label.lower():
                x,y,u,v=map(int,re.findall(r"\d+",node.get("bounds")))
                adb("shell","input","tap",str((x+u)//2),str((y+v)//2));return True
    wait(locate,18)

def select_download(filename):
    time.sleep(1)
    node_click("Show roots")
    node_click("Downloads")
    node_click(filename)
    time.sleep(1)

wait(lambda: js("document.querySelector('#engine')?.textContent==='ONLINE'"))
assert js("innerWidth>innerHeight")
shot("dashboard.png")
for page in ["Library","Performance","Graphics","Controller","Settings","Diagnostics","About","Dashboard"]:
    click("nav [data-page="+page+"]")
    assert js("page")==page
click('[data-act="play"]')
click('[data-num="1"]')
wait(lambda:js("document.querySelector('#dialogbody').textContent.includes('Guest breakpoint')"))
shot('execution.png')
click("#closeModal")
click('[data-act="featured"]');click('[data-act="favorite"]')
click("nav [data-page=Settings]")
js("let theme=document.querySelector('[data-pref=theme]');theme.value='violet';theme.dispatchEvent(new Event('change',{bubbles:true}))")
ws.close();adb("shell","am","force-stop",APP);ws=start()
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
print("PASS: landscape, all destinations, touch, JNI execution, favorites, theme restart, Android document selection, imported execution and invalid-file handling.")
