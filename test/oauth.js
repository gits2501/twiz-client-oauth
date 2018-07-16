var OAuth = require('../src/oauth_instrumented.js');
var assert     = require('assert');

var mockOAuth = { 

  leadPrefix: 'OAuth ',
  prefix: 'oauth_',

  oauth: {
     oauth_consumer_key: '',
     oauth_signature: '',
     oauth_nonce: '',
     oauth_signature_method: '',
     oauth_timestamp: '',
     oauth_version: '' 
  },

  request_token: { oauth_callback: '' },
  access_token: { oauth_token: '', oauth_verifier: '' },
  apiCall: { oauth_token: '' }
  
}
var mockNonce = 'ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ';
var mockTimestamp = '1523528027'
var userOptions = {
    method: 'POST',
    path:'statuses/update.json',
    params:{
       status: "A bug walks carelessly."
    },
    body: 'of a rhino bug',
    encoding: 'json',
    beforeSend: function(){}
        
 }

 var args = {
   
   server_url: 'https://myserver.com',
   redirection_url: 'https://myapp.com/redirUrl',
   new_window :{
      name: "nature's pocket",
      features: 'resizable=yes,height=613,width=400,left=400,top=300'
   },
   callback_func: function(){},
   session_data: {
      id: 342,
      data: 'user data'
   },  
   options: userOptions
      
 };

var oa;
beforeEach(function(){
  oa = new OAuth();
})

describe('OAuth parts',function(){

   it('lead header prefix',function(){
      assert.equal(oa.leadPrefix, mockOAuth.leadPrefix);
   })
   it('parameter header prefix', function(){
      assert.equal(oa.prefix, mockOAuth.prefix);
   })
   
   it('basic oauth params', function(){
     assert.deepEqual(oa.oauth, mockOAuth.oauth);
   })

   it('oauth params for request token leg', function(){
     assert.deepEqual(oa[oa.leg[0]], mockOAuth.request_token);
   })
 
   it('oauth params for access token leg', function(){
     assert.deepEqual(oa[oa.leg[2]], mockOAuth.access_token);
   })

   it('oauth params for twitter api calls (after oauth)', function(){
     assert.deepEqual(oa.apiCall, mockOAuth.apiCall);
   })
 
     
})

 
describe('set general OAuth params', function(){ // sets oauth params needed for every oauth leg (step)
   

   
   
  it('signature_method', function(){ 
     oa.setUserParams(args); 
     oa.setNonUserParams();  

    assert.ok(typeof oa.oauth[oa.prefix + 'signature_method'] === 'string');
  })

  it('nonce - length 42 chars', function(){
     oa.setNonUserParams(); 
     assert.ok(oa.oauth[oa.prefix + 'nonce'].length === 42);
  })
 
  it('timestamp', function(){
    assert.ok(typeof(oa.oauth[oa.prefix + 'timestamp']/10000) === 'number');
  })

  it('version', function(){
    assert.ok(typeof(oa.oauth[oa.prefix + 'version']/1) === 'number');
  })
  
  it('consumer_key = \'\'', function(){
    assert.equal(oa.oauth[oa.prefix + 'consumer_key'], '');
  })

  it('signature = \'\'', function(){
    assert.equal(oa.oauth[oa.prefix + 'signature'], '');
  })
})

describe('request token OAuth params',function(){ // check request token params
    
  it('oauth_callback', function(){   

    oa.setUserParams(args); 
    assert.ok(oa[oa.leg[0]].oauth_callback);
  })
})

describe('access token OAuth params', function(){  // check access token params
    
   it('oauth_token', function(){
     assert.ok(oa[oa.leg[2]].hasOwnProperty('oauth_token'));
   })

   it('oauth_verifier', function(){
     assert.ok(oa[oa.leg[2]].hasOwnProperty('oauth_verifier'));
   })
    
})

describe('api call OAuth params', function(){  // check api call params
    
   it('oauth_token', function(){
     assert.ok(oa.apiCall.hasOwnProperty('oauth_token'));
   })
    
})

describe('add request token params to OAuth', function(){


   
   it('oauth_callback' , function(){
     oa.setUserParams(args); 
     oa.setNonUserParams();
     oa.OAuthParams('add', oa.oauth, oa[oa.leg[0]]); // add request token params to oauth
    
     assert.ok(oa.oauth['oauth_callback'])
   })
})

describe('add access token params to OAuth', function(){

     
   it(' removed - oauth_callback', function(){
      
      oa.setUserParams(args);
      oa.setNonUserParams();
      
      oa.OAuthParams('add', oa.oauth, oa[oa.leg[0]]); // add request token params to oauth
      oa.OAuthParams('remove', oa.oauth, oa[oa.leg[0]]) // remove oauth_callback

      assert.ok(!oa.oauth.hasOwnProperty('oauth_callback'));
   })
   
  
   it('oauth_token', function(){ 
     oa.OAuthParams('add', oa.oauth, oa[oa.leg[2]]); // add request token params to oauth
     assert.ok(oa.oauth.hasOwnProperty('oauth_token'));
   })
   
   it('oauth_verifier', function(){
     oa.OAuthParams('add', oa.oauth, oa[oa.leg[2]]); // add request token params to oauth
     assert.ok(oa.oauth.hasOwnProperty('oauth_verifier'));
   })
})

describe('add Query String parametars (request_token leg)', function(){
 
   var mockQp 
   var qp;  
   
   before(function(){
     mockQp = {            // mock query params object
       legHost: 'api.twitter.com',
       legPath: '/oauth/request_token',
       legMethod: 'POST',
       legSBS: 'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttps%253A%252F%252Fmyapp.com%252FredirUrl%253Fdata%253Did%25253D342%252526data%25253Duser%25252520data%26oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_version%3D1.0',
       legAH: 'OAuth oauth_callback="https%3A%2F%2Fmyapp.com%2FredirUrl%3Fdata%3Did%253D342%2526data%253Duser%252520data", oauth_consumer_key="", oauth_nonce="ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ", oauth_signature="", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1523528027", oauth_version="1.0"' }


      oa.setUserParams(args);
      oa.setNonUserParams();
      oa.OAuthParams('remove', oa.oauth, oa[oa.leg[2]]) // remove token and verifier params
      oa.OAuthParams('add', oa.oauth, oa[oa.leg[0]])    // add oauth_callback
  
      oa.setRequestOptions(oa.leg[0]);

   
      oa.oauth.oauth_nonce = "ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ"; // set nonce so it doesnt change 
                                                                        // (needs to be tested with assert.equal())
      oa.oauth.oauth_timestamp = '1523528027';                             // set timestamp so it doesnt change

      oa.addQueryParams('leg', oa.leg[0]) // add query params for request token leg

      qp = oa.options.queryParams;
   })

   it('(leg) Host', function(){ 

       assert.equal(qp.legHost, mockQp.legHost);
   })

   it('(leg) Path', function(){
     assert.equal(qp.legPath, mockQp.legPath);
   })

   it('(leg) Method', function(){
     assert.equal(qp.legMethod, mockQp.legMethod);
   })
   

   it('(leg) Signature Base String - with session data', function(){
      assert.equal(qp.legSBS, mockQp.legSBS) 
   })
 
   it('(leg) Authorization Header String', function(){
      assert.equal(qp.legAH, mockQp.legAH)
   })
  

   
   
   it('(leg) Signature Base String', function(){
      oa.setUserParams(args);
      oa.setNonUserParams();
      oa.oauth.oauth_nonce = mockNonce;         
      oa.oauth.oauth_timestamp = mockTimestamp;

      mockQp.legSBS = 'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttps%253A%252F%252Fmyapp.com%252FredirUrl%26oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_version%3D1.0';
   
      oa.session_data = '';                            // prepare for testing SBS with no session data
      oa.oauth.oauth_callback = args.redirection_url // reseting redir url so it doesnt contain session data
   
      oa.addQueryParams('leg', oa.leg[0]) // set again params so it can regenerate SBS without session data
      oa.setRequestOptions(oa.leg[0]);
      
      qp = oa.options.queryParams;

      assert.equal(qp.legSBS, mockQp.legSBS); 
   })
   
}) 

describe('add Query Parameters (request token leg  + api call)', function(){
 var mockQp;
 var qp;

 before(function(){ 
    mockQp = {                 // mock request token and api call params
      legHost: 'api.twitter.com',
      legPath: '/oauth/request_token',
      legMethod: 'POST',
      legSBS: 'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttps%253A%252F%252Fmyapp.com%252FredirUrl%26oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_version%3D1.0',
      legAH: 'OAuth oauth_callback="https%3A%2F%2Fmyapp.com%2FredirUrl", oauth_consumer_key="", oauth_nonce="ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ", oauth_signature="", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1523528027", oauth_version="1.0"',
      apiHost: 'api.twitter.com',
      apiPath: '/1.1/statuses/update.json?status=A%20bug%20walks%20carelessly.',
      apiMethod: 'POST',
      apiSBS: 'POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&oauth_callback%3Dhttps%253A%252F%252Fmyapp.com%252FredirUrl%26oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_version%3D1.0',
      apiAH: 'OAuth oauth_callback="https%3A%2F%2Fmyapp.com%2FredirUrl", oauth_consumer_key="", oauth_nonce="ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ", oauth_signature="", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1523528027", oauth_version="1.0"' 
   }

     oa.OAuthParams('add', oa.oauth, oa[oa.leg[0]]);  // add oauth params for request token leg
     oa.addQueryParams('api', oa.UserOptions);        // add params needed for api
     qp = oa.options.queryParams;    
 
   })

   it('(api) Host', function(){
      assert.equal(qp.apiHost, mockQp.apiHost);
   })
    
   it('(api) Path', function(){
     assert.equal(qp.apiPath, mockQp.apiPath);
   })

   it('(api) Method', function(){
     assert.equal(qp.apiMethod, mockQp.apiMethod);
   })

   it('(api) Signature Base String', function(){   
     assert.equal(qp.apiSBS, mockQp.apiSBS);
   })
  
   it('(api) Authorization Header String', function(){
     assert.equal(qp.apiAH, mockQp.apiAH);
   })

   it('(request token) + (api) query params', function(){
     assert.deepEqual(qp, mockQp)
   })
   
})

describe('add Query String parametars (access_token leg)', function(){
   var mockQp;
   var qp;

   before(function(){ 
     mockQp = { 
        legHost: 'api.twitter.com',
        legPath: '/oauth/access_token',
        legMethod: 'POST',
        legSBS: 'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_token%3D%26oauth_verifier%3D%26oauth_version%3D1.0',
        legAH: 'OAuth oauth_consumer_key="", oauth_nonce="ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ", oauth_signature="", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1523528027", oauth_token="", oauth_verifier="", oauth_version="1.0"' 

     }
     oa.setUserParams(args);
     oa.setNonUserParams();
     oa.oauth.oauth_nonce = mockNonce;          // set nonce to the one from mockQp so it doesnt change  
     oa.oauth.oauth_timestamp = mockTimestamp;  // set timestamp

     oa.OAuthParams('remove', oa.oauth, oa[oa.leg[0]]) // remove callback
     oa.OAuthParams('add', oa.oauth, oa[oa.leg[2]])    // add token and verifier params
  
     oa.setRequestOptions(oa.leg[2]);
   
                               // set timestamp so it doesnt change

     oa.addQueryParams('leg', oa.leg[2]) // add query params for access token leg


     qp = oa.options.queryParams;
   })
  
   it('(leg) Host', function(){ 
     assert.equal(qp.legHost, mockQp.legHost);
   })
  
   it('(leg) Path', function(){
     assert.equal(qp.legPath, mockQp.legPath);
   })

   it('(leg) Method', function(){
     assert.equal(qp.legMethod, mockQp.legMethod);
   })

   it('(leg) Signature Base String', function(){ 
     assert.equal(qp.legSBS, mockQp.legSBS) 
   })

   it('(leg) Authorization Header String', function(){
     assert.equal(qp.legAH, mockQp.legAH);
   })
  
}) 

describe('add Query String parametars (access_token plus)', function(){ // test access token and api params
   var mockQp;
   var qp;

   before(function(){ 
      mockQp = {               // mocks query params needed for "oauth access token plus" request 
        legHost: 'api.twitter.com',
        legPath: '/oauth/access_token',
        legMethod: 'POST',
        legSBS: 'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_token%3D%26oauth_verifier%3D%26oauth_version%3D1.0',
        legAH: 'OAuth oauth_consumer_key="", oauth_nonce="ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ", oauth_signature="", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1523528027", oauth_token="", oauth_verifier="", oauth_version="1.0"',
        apiHost: 'api.twitter.com',
        apiPath: '/1.1/statuses/update.json?status=A%20bug%20walks%20carelessly.',
        apiMethod: 'POST',
        apiSBS: 'POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_token%3D%26oauth_version%3D1.0',
        apiAH: 'OAuth oauth_consumer_key="", oauth_nonce="ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ", oauth_signature="", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1523528027", oauth_token="", oauth_version="1.0"' 
      }
  
      oa.setUserParams(args);
      oa.setNonUserParams();
       
      oa.oauth.oauth_nonce = mockNonce;                 // set nonce so it doesnt change 
      oa.oauth.oauth_timestamp = mockTimestamp;         // set timestamp so it doesnt change

      oa.OAuthParams('remove', oa.oauth, oa[oa.leg[2]]) // remove  token and verifier params
      oa.OAuthParams('add', oa.oauth, oa.apiCall)       // add callback
  
      oa.addQueryParams('api', oa.UserOptions) // add query params for api call
     
      oa.setRequestOptions(oa.leg[2]);

      qp = oa.options.queryParams
   })
   
   it('(api) Host', function(){
     assert.equal(qp.apiHost, mockQp.apiHost);
   })

   it('(api) Path', function(){
     assert.equal(qp.apiPath, mockQp.apiPath);
   })         
  
   it('(api) Method', function(){
     assert.equal(qp.apiMethod, mockQp.apiMethod);
   })
   
   it('(api) Signature Base String', function(){ 
     assert.equal(qp.apiSBS, mockQp.apiSBS);
   })

   it('(api) Authorization Header String', function(){
     assert.equal(qp.apiAH, mockQp.apiAH);
   })

   before(function(){

      oa.setUserParams(args);
      oa.setNonUserParams();
       
      oa.oauth.oauth_nonce = mockNonce;                 // set nonce so it doesnt change 
      oa.oauth.oauth_timestamp = mockTimestamp;         // set timestamp so it doesnt change

      oa.OAuthParams('remove', oa.oauth, oa.apiCall)    // remove token
      oa.OAuthParams('add', oa.oauth, oa[oa.leg[2]])    // add  token and verifier params (access token params)
  
      oa.addQueryParams('leg', oa.leg[2])         // add query params for api call
     
      oa.setRequestOptions(oa.leg[2]);

      qp = oa.options.queryParams
   })

   it('(access token) + (api) query params', function(){  
     assert.deepStrictEqual(qp, mockQp)
   })
   
}) 



