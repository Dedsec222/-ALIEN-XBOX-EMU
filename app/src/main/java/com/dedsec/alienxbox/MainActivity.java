package com.dedsec.alienxbox;

import android.app.*;
import android.os.*;
import android.content.*;
import android.database.Cursor;
import android.graphics.*;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.view.*;
import android.webkit.*;
import org.json.*;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainActivity extends Activity {
    static { System.loadLibrary("alien_core"); }
    private static native String diagnostic();
    private static final int MAX_PE_BYTES=256<<20;
    private static native String mappedImage(java.nio.ByteBuffer file,boolean run,int budget);
    private String mappedImage(File file,boolean run,int budget) throws IOException {
        try (java.nio.channels.FileChannel channel=new FileInputStream(file).getChannel()) {
            long size=channel.size();
            if(size==0 || size>MAX_PE_BYTES) throw new IOException("PE size outside supported range");
            return mappedImage(channel.map(java.nio.channels.FileChannel.MapMode.READ_ONLY,0,size),run,budget);
        }
    }
    private static native String execute(byte[] file,int choice,int target,boolean bundled,int budget);
    private static final String ROOT="https://genesis.invalid/";
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private final AtomicBoolean executing=new AtomicBoolean();
    private WebView web;
    private SharedPreferences prefs;
    private volatile String diagnostics="Probing native engine…";
    private String pendingArt="", pendingReport="";
    private volatile boolean closed;
    private long lastWall, lastCpu;
    private final Random random=new Random();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        prefs=getSharedPreferences("alien_teal_settings",MODE_PRIVATE);
        if(state!=null){pendingArt=state.getString("art","");pendingReport=state.getString("report","");}
        getWindow().getDecorView().setSystemUiVisibility(5894);
        web=new WebView(this);
        web.setBackgroundColor(0xff050b0d);
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setDomStorageEnabled(true);
        web.getSettings().setAllowFileAccess(false);
        web.getSettings().setAllowContentAccess(false);
        web.setWebViewClient(new WebViewClient(){
            @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r){return true;}
            @Override public WebResourceResponse shouldInterceptRequest(WebView v,WebResourceRequest r){
                String url=r.getUrl().toString();
                try {
                    if(url.startsWith(ROOT)){
                        String path=url.substring(ROOT.length());
                        path=r.getUrl().getPath().substring(1);
                        if(path.matches("art/[a-f0-9]{64}|art/doors"))
                            return new WebResourceResponse("image/jpeg",null,new FileInputStream(new File(getFilesDir(),path.replace('/','-')+".jpg")));
                        if(path.matches("index.html|app.js|style.css|portals.webp|alien.svg"))
                            return new WebResourceResponse(path.endsWith("js")?"text/javascript":path.endsWith("css")?"text/css":path.endsWith("svg")?"image/svg+xml":path.endsWith("webp")?"image/webp":"text/html",null,getAssets().open(path));
                    }
                } catch(IOException ignored){}
                return new WebResourceResponse("text/plain","UTF-8",404,"Missing",null,new ByteArrayInputStream(new byte[0]));
            }
        });
        WebView.setWebContentsDebuggingEnabled((getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE)!=0);
        web.addJavascriptInterface(new Bridge(),"Genesis");
        setContentView(web);
        io.execute(()->{
            diagnostics=diagnostic();
            String previous=prefs.getString("last_homebrew_uri","");
            if(!previous.isEmpty()){
                try{importFile(Uri.parse(previous));prefs.edit().remove("last_homebrew_uri").apply();}
                catch(Exception e){record("Migration",e.toString());}
            }
            event("updated","");
        });
        web.loadUrl(ROOT+"index.html");
    }
    private static JSONObject obj(Object... kv){
        JSONObject result=new JSONObject();
        try{for(int i=0;i<kv.length;i+=2)result.put((String)kv[i],kv[i+1]);}
        catch(JSONException e){throw new IllegalArgumentException(e);}return result;
    }
    private JSONArray array(String key){
        try{return new JSONArray(prefs.getString(key,"[]"));}catch(JSONException e){return new JSONArray();}
    }
    private synchronized void record(String label,String text){
        JSONArray old=array("logs"),logs=new JSONArray();
        logs.put(obj("label",label,"time",System.currentTimeMillis(),"text",text));
        for(int i=0;i<Math.min(79,old.length());i++)logs.put(old.opt(i));
        prefs.edit().putString("logs",logs.toString()).apply();
    }
    private void event(String kind,String value){
        runOnUiThread(()->{if(!closed) web.evaluateJavascript("window.receive && receive("+JSONObject.quote(kind)+","+JSONObject.quote(value)+")",null);});
    }
    private byte[] read(InputStream source,int limit) throws IOException{
        if(source==null)throw new IOException("Document unavailable.");
        try(InputStream input=source;ByteArrayOutputStream output=new ByteArrayOutputStream()){
            byte[] chunk=new byte[8192];int count;
            while((count=input.read(chunk))!=-1){
                if(output.size()+count>limit)throw new IOException("File exceeds "+(limit>>20)+" MiB.");
                output.write(chunk,0,count);
            }return output.toByteArray();
        }
    }
    private String name(Uri uri){
        try(Cursor c=getContentResolver().query(uri,new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){
            if(c!=null && c.moveToFirst() && c.getString(0)!=null)return c.getString(0);
        }catch(RuntimeException ignored){}return "Imported homebrew";
    }
    private void importFile(Uri uri) throws Exception{
        File temp=File.createTempFile("guest",".pe",getFilesDir());
        try {
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            long size=0;
            try(InputStream in=getContentResolver().openInputStream(uri); OutputStream out=new FileOutputStream(temp)){
                if(in==null)throw new IOException("Document unavailable");
                byte[] buffer=new byte[65536];
                for(int n;(n=in.read(buffer))!=-1;){
                    size+=n;
                    if(size>MAX_PE_BYTES)throw new IOException("PE exceeds 256 MiB");
                    digest.update(buffer,0,n);
                    out.write(buffer,0,n);
                }
            }
            String issue=mappedImage(temp,false,0);
            if(!issue.isEmpty())throw new IOException(issue);
            StringBuilder hash=new StringBuilder();
            for(byte b:digest.digest())hash.append(String.format(Locale.ROOT,"%02x",b));
            String id=hash.toString();
            JSONArray games=array("games");
            for(int i=0;i<games.length();i++)if(id.equals(games.getJSONObject(i).optString("id")))return;
            Files.move(temp.toPath(),new File(getFilesDir(),id+".pe").toPath(),java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            games.put(obj("id",id,"name",name(uri),"size",size,"added",System.currentTimeMillis()));
            prefs.edit().putString("games",games.toString()).commit();
        }finally{temp.delete();}
    }
    private void artwork(Uri uri,String id) throws IOException{
        if(!validId(id))throw new IOException("Select a game first.");
        byte[] image=read(getContentResolver().openInputStream(uri),8<<20);
        BitmapFactory.Options opts=new BitmapFactory.Options();opts.inJustDecodeBounds=true;
        BitmapFactory.decodeByteArray(image,0,image.length,opts);
        if(opts.outWidth<=0 || opts.outHeight<=0)throw new IOException("Unsupported artwork.");
        opts.inSampleSize=1;
        while(Math.max(opts.outWidth,opts.outHeight)/opts.inSampleSize>1200)opts.inSampleSize*=2;
        opts.inJustDecodeBounds=false;
        Bitmap bitmap=BitmapFactory.decodeByteArray(image,0,image.length,opts);
        if(bitmap==null)throw new IOException("Image decoder failed.");
        File temp=File.createTempFile("art",".jpg",getFilesDir());
        try {
            try(OutputStream out=new FileOutputStream(temp)){
                if(!bitmap.compress(Bitmap.CompressFormat.JPEG,88,out))throw new IOException("Artwork conversion failed.");
            }
            Files.move(temp.toPath(),new File(getFilesDir(),"art-"+id+".jpg").toPath(),java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }finally{bitmap.recycle();temp.delete();}
        prefs.edit().putLong("art-"+id,System.currentTimeMillis()).apply();
    }
    private static boolean validId(String id){return "doors".equals(id)||id.matches("[a-f0-9]{64}");}
    public class Bridge {
        @JavascriptInterface public String preferences(){return prefs.getString("dashboardPreferences","");}
        @JavascriptInterface public boolean savePreferences(String json){
            if(json==null || json.length()>262144)return false;
            try{new JSONObject(json);}catch(JSONException invalid){return false;}
            return prefs.edit().putString("dashboardPreferences",json).commit();
        }
        @JavascriptInterface public String snapshot(){
            JSONArray games=array("games");JSONArray all=new JSONArray();
            all.put(obj("id","doors","name","Alien Doors","size",1024,"added",0));
            for(int i=0;i<games.length();i++)all.put(games.opt(i));
            for(int i=0;i<all.length();i++){JSONObject g=all.optJSONObject(i);try{
                g.put("art",prefs.getLong("art-"+g.optString("id"),0));
            }catch(JSONException ignored){}}
            return obj("games",all,"logs",array("logs"),"diag",diagnostics,"device",Build.MANUFACTURER+" "+Build.MODEL,
                "android",Build.VERSION.RELEASE,"abi",Build.SUPPORTED_ABIS[0],"compact",prefs.getBoolean("compact",false)).toString();
        }
        @JavascriptInterface public synchronized String metrics(){
            ActivityManager.MemoryInfo m=new ActivityManager.MemoryInfo();
            ((ActivityManager)getSystemService(ACTIVITY_SERVICE)).getMemoryInfo(m);
            long now=SystemClock.elapsedRealtime(), cpu=android.os.Process.getElapsedCpuTime();
            int cores=Runtime.getRuntime().availableProcessors();
            int usage=lastWall==0 || now<=lastWall?-1:(int)Math.min(100,100*(cpu-lastCpu)/((now-lastWall)*cores));
            if(lastWall==0||now-lastWall>300){lastCpu=cpu;lastWall=now;}
            String[] levels={"Normal","Light","Moderate","Severe","Critical","Emergency","Shutdown"};
            int heat=Build.VERSION.SDK_INT>=29?((PowerManager)getSystemService(POWER_SERVICE)).getCurrentThermalStatus():-1;
            JSONArray pads=new JSONArray();
            for(int id:InputDevice.getDeviceIds()){
                InputDevice d=InputDevice.getDevice(id);
                if(d!=null && (d.supportsSource(InputDevice.SOURCE_GAMEPAD)||d.supportsSource(InputDevice.SOURCE_JOYSTICK)))pads.put(d.getName());
            }
            return obj("avail",m.availMem,"total",m.totalMem,"heap",Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory(),
                "cores",cores,"cpu",usage,"thermal",heat>=0 && heat<levels.length?levels[heat]:"Unavailable","pads",pads).toString();
        }
        @JavascriptInterface public void pick(String type,String id){runOnUiThread(()->{
            if(closed)return;
            boolean art=type.equals("art");
            if(art && !validId(id))return;
            pendingArt=id;
            try{startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType(art?"image/*":"*/*"),art?2:1);}catch(ActivityNotFoundException e){event("error","Document picker unavailable.");}
        });}
        @JavascriptInterface public void run(String id,int choice,int limit){
            if(!validId(id)||closed||!executing.compareAndSet(false,true))return;
            io.execute(()->{
                try{
                    boolean bundled="doors".equals(id);
                    long start=SystemClock.elapsedRealtimeNanos();
                    String result=bundled?execute(read(getAssets().open("doors.exe"),4<<20),choice,random.nextInt(3)+1,true,limit)
                        :mappedImage(new File(getFilesDir(),id+".pe"),true,limit);
                    String report=result+"\nExecution time: "+String.format(Locale.ROOT,"%.3f ms",(SystemClock.elapsedRealtimeNanos()-start)/1e6);
                    record(id,report);event("result",report);
                }catch(Exception e){record(id,e.toString());event("error",e.getMessage());}
                finally{executing.set(false);}
            });
        }
        @JavascriptInterface public String notices(){
            try{return new String(read(getAssets().open("NDK-NOTICE.txt"),256<<10),java.nio.charset.StandardCharsets.UTF_8);}
            catch(IOException ex){return ex.toString();}
        }
        @JavascriptInterface public void exportReport(){runOnUiThread(()->{
            if(closed)return;
            pendingReport=snapshot();
            try{startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json")
                .putExtra(Intent.EXTRA_TITLE,"alien-xbox-diagnostics.json"),3);}catch(ActivityNotFoundException e){event("error","Export unavailable.");}
        });}
        @JavascriptInterface public void probe(){if(!closed)io.execute(()->{diagnostics=diagnostic();event("updated","Probe complete");});}
        @JavascriptInterface public void haptic(){runOnUiThread(()->{if(!closed)web.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);});}
    }
    @Override protected void onActivityResult(int code,int result,Intent data){
        super.onActivityResult(code,result,data);
        if(result!=RESULT_OK||data==null||data.getData()==null)return;
        Uri uri=data.getData();String art=pendingArt,report=pendingReport;
        io.execute(()->{try{
            if(code==1)importFile(uri);
            else if(code==2)artwork(uri,art);
            else if(code==3){try(OutputStream out=getContentResolver().openOutputStream(uri,"wt")){
                if(out==null)throw new IOException("Cannot open destination.");out.write(report.getBytes("UTF-8"));}}
            else return;
            event("updated",code==1?"Homebrew added to library":code==2?"Artwork updated":"Report exported");
        }catch(Exception e){record("Document",e.toString());event("error",e.toString());}});
    }
    @Override public boolean dispatchKeyEvent(KeyEvent e){
        if(e.isFromSource(InputDevice.SOURCE_GAMEPAD) && !KeyEvent.isModifierKey(e.getKeyCode())){
            if(e.getAction()==KeyEvent.ACTION_DOWN && e.getRepeatCount()==0)event("pad",KeyEvent.keyCodeToString(e.getKeyCode()));
            return true;
        }return super.dispatchKeyEvent(e);
    }
    @Override protected void onSaveInstanceState(Bundle b){super.onSaveInstanceState(b);b.putString("art",pendingArt);b.putString("report",pendingReport);}
    @Override public void onBackPressed(){web.evaluateJavascript("window.goBack && goBack()",value->{if("false".equals(value))finish();});}
    @Override protected void onPause(){web.onPause();super.onPause();}
    @Override protected void onResume(){super.onResume();if(web!=null)web.onResume();}
    @Override protected void onDestroy(){closed=true;io.shutdownNow();web.removeJavascriptInterface("Genesis");web.destroy();super.onDestroy();}
}
