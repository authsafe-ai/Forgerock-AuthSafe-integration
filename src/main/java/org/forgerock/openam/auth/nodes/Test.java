package org.forgerock.openam.auth.nodes;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Test {
	public static void main(String[] args) throws IOException, InterruptedException, JSONException {		  
		  
	      String propertyID = "3115958146187663";
	      
	      String propertySecret = "oxHfSU0dHGkd1D6i";
	      
	      String plainCredentials = propertyID + ":" + propertySecret;
	      
	      String base64Credentials = new String(Base64.getEncoder().encode(plainCredentials.getBytes()));
	      
	      String authorizationHeader = "Basic " + base64Credentials;
	      
	      ObjectMapper mapper = new ObjectMapper();
	      
	      JSONObject object = new JSONObject();
	      object.put("ev", "login_succeeded");
	      object.put("dID", "eyJwdGwiOiJDbGllbnQgQXJlYSAtIFdheHNwYWNlIiwiZXYiOiJtX2wiLCJldCI6IjIwMjItMDItMjFUMTA6MzM6NDUuNTg3WiIsImNzIjoiVVRGLTgiLCJzciI6IjEzNjZ4NzY4IiwidnAiOiIxMzY2eDYyNSIsImNkIjoyNCwidHoiOi01LjUsImhjIjo4LCJtdCI6WyJhcHBsaWNhdGlvbi9wZGYiLCJ0ZXh0L3BkZiJdLCJwIjpbIlBERiBWaWV3ZXIiLCJDaHJvbWUgUERGIFZpZXdlciIsIkNocm9taXVtIFBERiBWaWV3ZXIiLCJNaWNyb3NvZnQgRWRnZSBQREYgVmlld2VyIiwiV2ViS2l0IGJ1aWx0LWluIFBERiJdLCJ0byI6IjIwMjItMDItMjFUMTA6MzM6MjguODUxWiIsInBvIjoiaHR0cHM6Ly93YXhzcGFjZS5jb20vY2xpZW50L2NsaWVudGFyZWEucGhwIiwicmYiOiIiLCJwcyI6MiwiYm4iOiJOZXRzY2FwZSIsImJsIjoiZW4tVVMiLCJqZSI6MCwibGUiOiJtX2wiLCJjZSI6MSwiYXgiOiJBY3RpdmVYIE9iamVjdCBub3Qgc3VwcG9ydGVkIiwicGFsIjpbXSwiX19hc3RrIjoiZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SmpkU0k2TXl3aWNISWlPalV6TENKelpYTnpYMmxrSWpvaU5URTNNakEzTmpJdE56SXpNaTAwT0RZMkxXSTBZbUl0TlRZMk9EYzJZVE16WW1Oa0lpd2lhV0YwSWpveE5qUTFORE01TVRnM0xDSmxlSEFpT2pFMk5EVTBPVFkzT0RkOS40QUFRRlBhd3BYUkFLdDVPTXFpbHVHSGpfX1hQcUQzR25rYXBaQnhJdnc0IiwidnNpIjoiNTE3MjA3NjItNzIzMi00ODY2LWI0YmItNTY2ODc2YTMzYmNkIiwidmRpIjoiMDJlOTYxNWItMGUxZC00ZmY4LTljMzYtZWM2ZjRlNjgyNzBiIiwiZWwiOiJpbnB1dCIsImVsSUQiOiJsb2dpbiIsImNsIjp7IjAiOiJidG4iLCIxIjoiYnRuLXByaW1hcnkifSwieCI6MCwieSI6MCwidiI6MH0=");
	      
	      JSONObject uex = new JSONObject();
	      uex.put("email", "jumbo.king@yopmail.com");
	      uex.put("username", "Jumbo");
	      
	      object.put("uex", uex);
	      
	      JSONObject h = new JSONObject();
	      h.put("ip", "45.252.74.134");
	      h.put("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36");
	      h.put("ho", "waxspace.com");
	      h.put("rf", "https://waxspace.com/client/clientarea.php");
	      
	      JSONObject ac = new JSONObject();
	      ac.put("a", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
	      ac.put("ac", "");
	      ac.put("ae", "gzip, deflate, br");
	      ac.put("al", "en-US,en;q=0.9,hi;q=0.8,mr;q=0.7");
	      
	      h.put("ac", ac);
	      h.put("url", "waxspace.com/client/dologin.php");
	      
	      object.put("h", h);
	      object.put("uID", "1986");
	      
	      String json = object.toString();
	      
	      System.out.println(json);
	      
//	      String json = "{\r\n"
//	      		+ "	\"ev\": \"login_succeeded\",\r\n"
//	      		+ "	\"dID\": \"eyJwdGwiOiJDbGllbnQgQXJlYSAtIFdheHNwYWNlIiwiZXYiOiJtX2wiLCJldCI6IjIwMjItMDItMjFUMTA6MzM6NDUuNTg3WiIsImNzIjoiVVRGLTgiLCJzciI6IjEzNjZ4NzY4IiwidnAiOiIxMzY2eDYyNSIsImNkIjoyNCwidHoiOi01LjUsImhjIjo4LCJtdCI6WyJhcHBsaWNhdGlvbi9wZGYiLCJ0ZXh0L3BkZiJdLCJwIjpbIlBERiBWaWV3ZXIiLCJDaHJvbWUgUERGIFZpZXdlciIsIkNocm9taXVtIFBERiBWaWV3ZXIiLCJNaWNyb3NvZnQgRWRnZSBQREYgVmlld2VyIiwiV2ViS2l0IGJ1aWx0LWluIFBERiJdLCJ0byI6IjIwMjItMDItMjFUMTA6MzM6MjguODUxWiIsInBvIjoiaHR0cHM6Ly93YXhzcGFjZS5jb20vY2xpZW50L2NsaWVudGFyZWEucGhwIiwicmYiOiIiLCJwcyI6MiwiYm4iOiJOZXRzY2FwZSIsImJsIjoiZW4tVVMiLCJqZSI6MCwibGUiOiJtX2wiLCJjZSI6MSwiYXgiOiJBY3RpdmVYIE9iamVjdCBub3Qgc3VwcG9ydGVkIiwicGFsIjpbXSwiX19hc3RrIjoiZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SmpkU0k2TXl3aWNISWlPalV6TENKelpYTnpYMmxrSWpvaU5URTNNakEzTmpJdE56SXpNaTAwT0RZMkxXSTBZbUl0TlRZMk9EYzJZVE16WW1Oa0lpd2lhV0YwSWpveE5qUTFORE01TVRnM0xDSmxlSEFpT2pFMk5EVTBPVFkzT0RkOS40QUFRRlBhd3BYUkFLdDVPTXFpbHVHSGpfX1hQcUQzR25rYXBaQnhJdnc0IiwidnNpIjoiNTE3MjA3NjItNzIzMi00ODY2LWI0YmItNTY2ODc2YTMzYmNkIiwidmRpIjoiMDJlOTYxNWItMGUxZC00ZmY4LTljMzYtZWM2ZjRlNjgyNzBiIiwiZWwiOiJpbnB1dCIsImVsSUQiOiJsb2dpbiIsImNsIjp7IjAiOiJidG4iLCIxIjoiYnRuLXByaW1hcnkifSwieCI6MCwieSI6MCwidiI6MH0=\",\r\n"
//	      		+ "	\"uex\": {\r\n"
//	      		+ "		\"email\": \"jumbo.king@yopmail.com\",\r\n"
//	      		+ "		\"username\": \"Jumbo\"\r\n"
//	      		+ "	},\r\n"
//	      		+ "	\"h\": {\r\n"
//	      		+ "		\"ip\": \"45.252.74.134\",\r\n"
//	      		+ "		\"ua\": \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36\",\r\n"
//	      		+ "		\"ho\": \"waxspace.com\",\r\n"
//	      		+ "		\"rf\": \"https://waxspace.com/client/clientarea.php\",\r\n"
//	      		+ "		\"ac\": {\r\n"
//	      		+ "			\"a\": \"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\",\r\n"
//	      		+ "			\"ac\": \"\",\r\n"
//	      		+ "			\"ae\": \"gzip, deflate, br\",\r\n"
//	      		+ "			\"al\": \"en-US,en;q=0.9,hi;q=0.8,mr;q=0.7\"\r\n"
//	      		+ "		},\r\n"
//	      		+ "		\"url\": \"waxspace.com/client/dologin.php\"\r\n"
//	      		+ "	},\r\n"
//	      		+ "	\"uID\": 1986\r\n"
//	      		+ "}";
	        
//	      Map<Object, Object> map = null;
//	      
//	      try {
//
//	            // convert JSON string to Map
////	             map = mapper.readValue(json, Map.class);
//
//				// it works
//	             map = mapper.readValue(json, new TypeReference<Map<Object, Object>>() {});
//
//	            System.out.println(map);
//
//	        } catch (IOException e) {
//	            e.printStackTrace();
//	        }
  
	      HttpClient client = HttpClient.newHttpClient();
	      
//	      Map<Object, Object> data = new HashMap<>();
//	        data.put("ev", "login_succeeded");
//	        data.put("dID", "eyJwdGwiOiJDbGllbnQgQXJlYSAtIFdheHNwYWNlIiwiZXYiOiJtX2wiLCJldCI6IjIwMjItMDItMjFUMTA6MzM6NDUuNTg3WiIsImNzIjoiVVRGLTgiLCJzciI6IjEzNjZ4NzY4IiwidnAiOiIxMzY2eDYyNSIsImNkIjoyNCwidHoiOi01LjUsImhjIjo4LCJtdCI6WyJhcHBsaWNhdGlvbi9wZGYiLCJ0ZXh0L3BkZiJdLCJwIjpbIlBERiBWaWV3ZXIiLCJDaHJvbWUgUERGIFZpZXdlciIsIkNocm9taXVtIFBERiBWaWV3ZXIiLCJNaWNyb3NvZnQgRWRnZSBQREYgVmlld2VyIiwiV2ViS2l0IGJ1aWx0LWluIFBERiJdLCJ0byI6IjIwMjItMDItMjFUMTA6MzM6MjguODUxWiIsInBvIjoiaHR0cHM6Ly93YXhzcGFjZS5jb20vY2xpZW50L2NsaWVudGFyZWEucGhwIiwicmYiOiIiLCJwcyI6MiwiYm4iOiJOZXRzY2FwZSIsImJsIjoiZW4tVVMiLCJqZSI6MCwibGUiOiJtX2wiLCJjZSI6MSwiYXgiOiJBY3RpdmVYIE9iamVjdCBub3Qgc3VwcG9ydGVkIiwicGFsIjpbXSwiX19hc3RrIjoiZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SmpkU0k2TXl3aWNISWlPalV6TENKelpYTnpYMmxrSWpvaU5URTNNakEzTmpJdE56SXpNaTAwT0RZMkxXSTBZbUl0TlRZMk9EYzJZVE16WW1Oa0lpd2lhV0YwSWpveE5qUTFORE01TVRnM0xDSmxlSEFpT2pFMk5EVTBPVFkzT0RkOS40QUFRRlBhd3BYUkFLdDVPTXFpbHVHSGpfX1hQcUQzR25rYXBaQnhJdnc0IiwidnNpIjoiNTE3MjA3NjItNzIzMi00ODY2LWI0YmItNTY2ODc2YTMzYmNkIiwidmRpIjoiMDJlOTYxNWItMGUxZC00ZmY4LTljMzYtZWM2ZjRlNjgyNzBiIiwiZWwiOiJpbnB1dCIsImVsSUQiOiJsb2dpbiIsImNsIjp7IjAiOiJidG4iLCIxIjoiYnRuLXByaW1hcnkifSwieCI6MCwieSI6MCwidiI6MH0=");
//	        data.put("uex", "");
//	        data.put("h", "");
//	        data.put("uID", 1986);
	      
	      HttpRequest request = HttpRequest.newBuilder()
	                .uri(URI.create("https://a.authsafe.ai/v1/login"))
//	    		    .uri(URI.create("https://httpbin.org/post"))
//	                .POST(ofFormData(map))
	                .POST(BodyPublishers.ofString(json))
//	                .GET()
	                .header("Authorization", authorizationHeader)
	                .header("Content-Type", "application/json")
//	                .header("Accept","application/json") 
	                .build();
	      
	      HttpResponse<String> response = client.send(request,
	                HttpResponse.BodyHandlers.ofString());
	      
	      ResponseBO obj = new Gson().fromJson(response.body(), ResponseBO.class);
	      
	      System.out.println(obj.status);

	        System.out.println(response.toString());
	        System.out.println(request.headers());
	        System.out.println(request.method());
	        System.out.println(request.uri());
	        System.out.println(response.body());
	        	        
	}
}