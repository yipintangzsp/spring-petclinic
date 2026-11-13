import java.net.URI;
import java.net.http.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
// Synthetic credentials only; no real user or response body is persisted.
public class ZapAuthProbe {
 static final HttpClient C=HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(5)).build();
 static String probe(String label,String url,String token,String cookie,Integer expected)throws Exception{
  var b=HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET();
  if(!token.isEmpty())b.header("Authorization","Bearer "+token);
  if(!cookie.isEmpty())b.header("Cookie",cookie);
  var r=C.send(b.build(),HttpResponse.BodyHandlers.ofByteArray());
  if(expected!=null&&r.statusCode()!=expected)throw new IllegalStateException("Fixture mismatch "+label+": "+r.statusCode());
  String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(r.body()));
  return "{\"case\":\""+label+"\",\"method\":\"GET\",\"status\":"+r.statusCode()+",\"bodySha256\":\""+hash+"\",\"bodyBytes\":"+r.body().length+"}";
 }
 public static void main(String[]a)throws Exception{
  String base=a[0];URI u=URI.create(base);
  if(!"http".equals(u.getScheme())||!u.getHost().matches("10\\.43\\.[0-9]{1,3}\\.[0-9]{1,3}")||u.getUserInfo()!=null||!u.getPath().isEmpty())throw new IllegalArgumentException("Fixed Service base required");
  String loop="http"+"://127.0.0.1:18083";List<String> f=new ArrayList<>(),b=new ArrayList<>();
  for(int i=0;i<2;i++){
   f.add(probe("anonymous-protected-r"+i,loop+"/protected","","",401));
   f.add(probe("alice-protected-r"+i,loop+"/protected","fixture-alice","",200));
   f.add(probe("alice-admin-r"+i,loop+"/admin","fixture-alice","",403));
   f.add(probe("admin-admin-r"+i,loop+"/admin","fixture-admin","",200));
   f.add(probe("alice-own-r"+i,loop+"/owned/alice","fixture-alice","",200));
   f.add(probe("bob-other-r"+i,loop+"/owned/alice","fixture-bob","",403));
   f.add(probe("invalid-r"+i,loop+"/protected","fixture-invalid","",401));
   f.add(probe("expired-fixture-r"+i,loop+"/protected","fixture-expired","",401));
   f.add(probe("removed-r"+i,loop+"/protected","","",401));
   boolean detected=false;try{probe("intentional-bypass-r"+i,loop+"/broken-protected","","",401);}catch(IllegalStateException expected){detected=true;}
   if(!detected)throw new IllegalStateException("Known-bad fixture was not detected");
   f.add("{\"case\":\"known-bad-bypass-r"+i+"\",\"detected\":true,\"scope\":\"synthetic-only\"}");
  }
  if(a.length<2||!a[1].equals("--fixture-only"))for(String p:new String[]{"/","/owners/find","/vets.html","/actuator/health"}){
   String k=p.equals("/")?"root":p.substring(1).replace('/','-');
   b.add(probe(k+"-none",base+p,"","",null));
   b.add(probe(k+"-invalid",base+p,"fixture-invalid","",null));
   b.add(probe(k+"-stale-cookie",base+p,"","JSESSIONID=fixture-invalid",null));
   b.add(probe(k+"-removed",base+p,"","",null));
  }
  System.out.println("{\"status\":\"success\",\"fixtureScope\":\"Synthetic role/ownership model only; not real PetClinic accounts or session revocation\",\"fixture\":["+String.join(",",f)+"],\"businessScope\":\"Existing public GET routes only; credential observations are not authorization bypass proof\",\"business\":["+String.join(",",b)+"],\"productionUnsupported\":[\"user/admin differential\",\"cross-user ownership\",\"valid/expired real tokens\",\"server session revocation\"]}");
 }
}
