var Options       = require('twiz-client-options');
var percentEncode = require('twiz-client-utils').percentEncode;
var formEncode    = require('twiz-client-utils').formEncode; 
var btoa;

if(typeof window === 'object' && window != null) btoa = window.btoa; 
else btoa = require('btoa');         // in node require node implementation of browser's btoa (used when testing)

   function OAuth(){                 // Prepares oauth strings for a request
      Options.call(this);
     
      this.leadPrefix = "OAuth "     // leading string afther all key-value pairs go. Notice space at the end. 
      this.prefix = "oauth_";        // Prefix for each oauth key in a http request
      
      this.oauth = {}                                // Holds parameters that are used to generate SBS and AH
      this.oauth[ this.prefix + 'consumer_key'] = "";// This is very sensitive data. Server sets the value.
      this.oauth[ this.prefix + 'signature'] = "";   // This value is also inserted in server code.
      this.oauth[ this.prefix + 'nonce'] =  "";     // Session id, twitter api uses this to determines duplicates
      this.oauth[ this.prefix + 'signature_method'] = ""; // Signature method we are using
      this.oauth[ this.prefix + 'timestamp'] = "";   // Unix epoch timestamp
      this.oauth[ this.prefix + 'version'] = ""      // all request use ver 1.0
      
      this[this.leg[0]] = {};                        // oauth param for request token step
      this[this.leg[0]][ this.prefix + 'callback'] = ''; // User is return to this link, 
                                                                          // if approval is confirmed   
      // this[this.leg[1]] = {}                     // there is no oauth params for authorize step. request_token                                                    // is sent as redirection url query parameter.
                               
      this[this.leg[2]] = {}                        // oauth params for access token step
      this[this.leg[2]][ this.prefix + 'token'] = '';  
      this[this.leg[2]][ this.prefix + 'verifier'] = '';
     
      this.apiCall = {}
      this.apiCall[ this.prefix + 'token'] = '';   // oauth param for api calls. Here goes just users acess token
                                                   // (inserted by server code)
      
      this.OAuthParams = function(action, o1, o2){      // Props found in o2 adds or removes from o1
          Object.getOwnPropertyNames(o2)
                  .map(function(key, i){
                       if(action === 'add') o1[key] = o2[key]; // add property name and value from o2 to o1
                       else delete o1[key];                    // removes property name we found in o2 from o1 
                   })
          return o1;
      }

       
   }

   OAuth.prototype = Object.create(Options.prototype);

   OAuth.prototype.setNonUserParams = function(){ // sets all "calculated" oauth params 
      this.setSignatureMethod();
      this.setNonce();
      this.setTimestamp();
      this.setVersion();
   }
   
   OAuth.prototype.setSignatureMethod = function(method){
      this.oauth[this.prefix + 'signature_method'] = method || "HMAC-SHA1";
   }

   OAuth.prototype.setVersion = function(version){ 
      this.oauth[ this.prefix + 'version'] =  version || "1.0";
   }

   OAuth.prototype.setNonce = function(){ // Generates string from random sequence of 32 numbers, 
                                          // then returns base64 encoding of that string, striped of "=" sign.
      var seeds = "AaBb1CcDd2EeFf3GgHh4IiJjK5kLl6MmN7nOo8PpQqR9rSsTtU0uVvWwXxYyZz"; 
      var nonce = "";
  
      for(var i = 0; i < 31; i++){
        nonce += seeds[Math.round(Math.random() * (seeds.length - 1))];// pick a random ascii from seeds string
      }
    
      nonce = btoa(nonce).replace(/=/g,"");       // encode to base64 and strip the "=" sign
     //  console.log("nonce: " + nonce)
      this.oauth[ this.prefix + 'nonce'] = nonce; // set twitter session identifier (nonce)
   }

   OAuth.prototype.setTimestamp = function(){
      this.oauth[ this.prefix + 'timestamp'] = (Date.now() / 1000 | 0) + 1;// cuting off decimal part by 
                                                   // converting it to 32 bit integer in bitwise OR operation. 
   }

   OAuth.prototype.addQueryParams = function(phase, leg){ // 'phase' indicates for which type of request we are
                                                          // adding params. 
    //  console.log('addQueryParams phase:', phase +'' );
      this.options.queryParams[phase + 'Host']   = this.twtUrl.domain;
      this.options.queryParams[phase + 'Path']   = phase === 'leg' ? this.twtUrl.path + leg : 
                                                                    this.twtUrl.api_path +
                                                                    this.UserOptions.path +
                                                                    this.UserOptions.paramsEncoded;
     
      this.options.queryParams[phase + 'Method'] = phase === 'leg' ? this.httpMethods[leg] : this.UserOptions.method;
      this.options.queryParams[phase + 'SBS']    = this.genSignatureBaseString(leg); 
      this.options.queryParams[phase + 'AH']     = this.genHeaderString();
   }
   
   OAuth.prototype.genSignatureBaseString = function(leg){    // generates SBS  
         this.signatureBaseString = '';
         var a = [];
         for(var name in this.oauth){                         // takes every oauth params name
            if(this.oauth.hasOwnProperty(name)) a.push(name); // and pushes them to array
         } 
     
         a.sort();  // sorts alphabeticaly

         var pair;  // key value pair
         var key;   // parameter name
         var value; // param value   
                                              // Collects oauth params
         for(var i = 0; i < a.length; i++){   // Percent encodes every key value, puts "=" between those, and
                                              // between each pair of key/value it puts "&" sign.
            key = a[i];                       // Thakes key that was sorted alphabeticaly
            switch(key){                      // In case of consumer and user keys we leave them to server logic
              case "oauth_callback":   // Callback url to which users are redirected by twitter         
                                       // Check to see if there is data to append to calback as query string:
                value = this.session_data ? this.appendToCallback(this.session_data) : 
                                                this.oauth[this.prefix + 'callback']; 
              break; 
              case "oauth_consumer_key": 
                value = "";             // Sensitive data we leave for server to add
              break;   
              case "oauth_signature":
                continue;              // We dont add signature to singatureBaseString at all
              break;
              default:
                value = this.oauth[key];          // Takes value of that key
            }
            pair = percentEncode(key) + "=" + percentEncode(value); // Encodes key value and inserts "="
          console.log(pair)                                         // in between.
            if(i !== a.length - 1) pair += "&"; // Dont append "&" on last pair    
            this.signatureBaseString += pair;   // Add pair to SBS
         } 

         var method;  // Collecting the reqest method and url
         var url;

         if(typeof leg === 'string'){            // we are in 3-leg dance, take well known params
           method = this.httpMethods[leg]        // Get the method for this leg
           method = method.toUpperCase() + "&";  // upercase the method, add "&"

           url = this.absoluteUrls[leg];         // Get the absolute url for this leg of authentication
           url = percentEncode(url) + "&";       // Encode the url, add "&".
         }
         else {                                      // 'leg' is the options object user provided     
           method = leg.method.toUpperCase() + "&";  // Upercase the method, add "&"
           url = this.twtUrl.protocol + this.twtUrl.domain + this.twtUrl.api_path + leg.path;     
                                                     // Get the absoute url for api call + user provided path
           url = percentEncode(url) + "&";           // Encode the url, add "&".
         }
         // Finaly we assemble the sbs string. PercentEncoding again the signature base string.
         this.signatureBaseString = method + url + percentEncode(this.signatureBaseString);
     //    console.log("SBS string: "+ this.signatureBaseString); 
        return this.signatureBaseString;
   }

   OAuth.prototype.genHeaderString = function(){
      var a = [];
       
      Object.getOwnPropertyNames(this.oauth)
      .forEach(function(el){ if(!/^oauth/.test(el)) delete this[el] }, this.oauth) // delete non oauth params
      
      for(var name in this.oauth){
          a.push(name);
      }
      console.log("a; " + a);
      a.sort();                           // Aphabeticaly sort array of property names

      var headerString = this.leadPrefix; // Adding "OAuth " in front everthing
      var key;                            // Temp vars
      var value;
      var pair;
    
      for(var i = 0; i < a.length; i++){  // iterate oauth  
         
          key = a[i];                                    // Take the key name (sorted in a)

          value = this.oauth[key];   // Get it from oauth object
      
          key = percentEncode(key);  // Encode the key
          value = "\"" + percentEncode(value) + "\"";    // Adding double quotes to value
          
          pair = key + "=" + value;                  // Adding "=" between
          if(i !== (a.length - 1)) pair = pair + ", " // Add trailing comma and space, until end

          headerString += pair;       
      } 
     // console.log("AHS string: " + headerString); 
      return headerString;
   }

   OAuth.prototype.appendToCallback = function(data, name){ // appends data object as querystring to                                                                         // oauth_callback url. 
      console.log('Data: ==> ', data)
      if(!name) name = "data";
      var callback = this.oauth[ this.prefix + 'callback'];
      var fEncoded = formEncode(data, true);

      //console.log(fEncoded);
      var queryString = name + '=' + percentEncode(fEncoded); // Make string from object then                                                                                  // percent encode it.  
      //console.log("queryString: ", queryString)
    
      if(!/\?/.test(callback)) callback += "?";               // Add "?" if one not exist
      else queryString =  '&' + queryString                   // other queryString exists, so add '&' to this qs
      this.oauth[ this.prefix + 'callback'] = callback + queryString;           // Add queryString to callback
                                                     
    //   console.log("OAUTH CALLBACK: "+this.oauth[ this.prefix + 'callback'])
      return this.oauth[ this.prefix + 'callback'];
   };

   module.exports = OAuth;
