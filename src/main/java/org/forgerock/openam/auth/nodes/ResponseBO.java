package org.forgerock.openam.auth.nodes;

public class ResponseBO {
   String status;
   String severity;
   deviceInformation device;
   String message;   
}

class deviceInformation{
    String device_id;
    String name;
    String ip;
    String location;
    
}
