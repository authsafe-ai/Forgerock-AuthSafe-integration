package org.forgerock.openam.auth.nodes;

public class Test {
  public static void main(String[] args) {
	  String script = "var script = document.createElement('script');\n" +
              "script.type = 'text/javascript';\n" +
              "script.src = '%1$s'\n" +                
              "document.getElementsByTagName('head')[0].appendChild(script);\n" +
              "var requestStringscript = document.createElement('script');\n" +
              "var requestString = '%2$s'\n"+
              "requestStringscript.appendChild(requestString);\n" +
              "document.getElementsByTagName('head')[0].appendChild(requestStringscript);\n";

	  System.out.println(script);
}
}
