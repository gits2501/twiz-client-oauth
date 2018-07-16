var test = require('tap').test;
var OAuth = require('../src/OAuth');
var oa = new OAuth();

 
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

test('OAuth parts',function(t){
    t.plan(6);

    t.equals(oa.leadPrefix, mockOAuth.leadPrefix, 'lead header prefix');
    t.equals(oa.prefix, mockOAuth.prefix, 'parameter header prefix');

    t.deepEquals(oa.oauth, mockOAuth.oauth, 'basic oauth params');
    t.deepEquals(oa[oa.leg[0]], mockOAuth.request_token, 'oauth params for request token leg');
    t.deepEquals(oa[oa.leg[2]], mockOAuth.access_token, 'oauth params for access token leg');
    t.deepEquals(oa.apiCall, mockOAuth.apiCall, 'oauth params for twitter api calls (after oauth)');

     
})

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

test('set general OAuth params', function(t){ // sets oauth params needed for every oauth leg (step)
   
    t.plan(6);

    oa.setUserParams(args); 
   
    oa.setNonUserParams();  
    
    t.ok(typeof oa.oauth[oa.prefix + 'signature_method'] === 'string', 'signature_method');
    t.ok(oa.oauth[oa.prefix + 'nonce'].length === 42, 'nonce - length 42 chars');
    t.ok(typeof(oa.oauth[oa.prefix + 'timestamp']/10000) === 'number', 'timestamp');
    t.ok(typeof(oa.oauth[oa.prefix + 'version']/1) === 'number', 'version');
  
    t.equals(oa.oauth[oa.prefix + 'consumer_key'], '', 'consumer_key = \'\'');
    t.equals(oa.oauth[oa.prefix + 'signature'], '', 'signature = \'\'');
})

test('request token OAuth params',function(t){ // check request token params
    
    t.plan(1);
    
    t.ok(oa[oa.leg[0]].oauth_callback, 'oauth_callback');
})

test('access token OAuth params', function(t){  // check access token params
    
    t.plan(2);

    t.ok(oa[oa.leg[2]].hasOwnProperty('oauth_token'),'oauth_token');
    t.ok(oa[oa.leg[2]].hasOwnProperty('oauth_verifier'),'oauth_verifier');
    
})

test('api call OAuth params', function(t){  // check api call params
    
    t.plan(1);

    t.ok(oa.apiCall.hasOwnProperty('oauth_token'),'oauth_token');
    
})

test('add request token params to OAuth', function(t){

    t.plan(1);

    oa.OAuthParams('add', oa.oauth, oa[oa.leg[0]]); // add request token params to oauth
    t.ok(oa.oauth['oauth_callback'], 'oauth_callback')
})

test('add access token params to OAuth', function(t){

    t.plan(3);
     
    oa.OAuthParams('remove', oa.oauth, oa[oa.leg[0]]) // remove oauth_callback
    t.notOk(oa.oauth.hasOwnProperty('oauth_callback'), ' removed - oauth_callback');
    
    oa.OAuthParams('add', oa.oauth, oa[oa.leg[2]]); // add request token params to oauth
    t.ok(oa.oauth.hasOwnProperty('oauth_token'), 'oauth_token')
    t.ok(oa.oauth.hasOwnProperty('oauth_verifier'), 'oauth_verifier')
})

test('add Query String parametars (request_token leg)', function(t){
    t.plan(6);   
 
   var mockQp = {            // mock query params object
     legHost: 'api.twitter.com',
     legPath: '/oauth/request_token',
     legMethod: 'POST',
     legSBS: 'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttps%253A%252F%252Fmyapp.com%252FredirUrl%253Fdata%253Did%25253D342%252526data%25253Duser%25252520data%26oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_version%3D1.0',
     legAH: 'OAuth oauth_callback="https%3A%2F%2Fmyapp.com%2FredirUrl%3Fdata%3Did%253D342%2526data%253Duser%252520data", oauth_consumer_key="", oauth_nonce="ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ", oauth_signature="", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1523528027", oauth_version="1.0"' }

   oa.OAuthParams('remove', oa.oauth, oa[oa.leg[2]]) // remove token and verifier params
   oa.OAuthParams('add', oa.oauth, oa[oa.leg[0]])    // add oauth_callback
  
   oa.setRequestOptions(oa.leg[0]);

   
   oa.oauth.oauth_nonce = "ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ"; // set nonce so it doesnt change 
                                                                        // (needs to be tested with t.equals())
   oa.oauth.oauth_timestamp = '1523528027';                             // set timestamp so it doesnt change

   oa.addQueryParams('leg', oa.leg[0]) // add query params for request token leg

   var qp = oa.options.queryParams;
   
   t.equals(qp.legHost, mockQp.legHost,'(leg) Host');
   t.equals(qp.legPath, mockQp.legPath,'(leg) Path');
   t.equals(qp.legMethod, mockQp.legMethod,'(leg) Method');
   
   // 
   t.equals(qp.legSBS, mockQp.legSBS, '(leg) Signature Base String - with session data') 
   t.equals(qp.legAH, mockQp.legAH, '(leg) Authorization Header String')
  

   mockQp.legSBS = 'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Frequest_token&oauth_callback%3Dhttps%253A%252F%252Fmyapp.com%252FredirUrl%26oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_version%3D1.0';
   
   oa.session_data = ''; // prepare for testing SBS with no session data
   oa.oauth.oauth_callback = args.redirection_url // reseting redir url so it doesnt contain session data
   
   oa.addQueryParams('leg', oa.leg[0]) // set again params so it can regenerate SBS without session data
   
   t.equals(qp.legSBS, mockQp.legSBS, '(leg) Signature Base String'); 
   
}) 

test('add Query Parameters (request token leg  + api call)', function(t){
  t.plan(6); 
 
  var mockQp = {                 // mock request token and api call params
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

   var qp = oa.options.queryParams;    
   t.equals(qp.apiHost, mockQp.apiHost, '(api) Host');
   t.equals(qp.apiPath, mockQp.apiPath, '(api) Path');
   t.equals(qp.apiMethod, mockQp.apiMethod, '(api) Method');
   
   t.equals(qp.apiSBS, mockQp.apiSBS, '(api) Signature Base String');
   t.equals(qp.apiAH, mockQp.apiAH, '(api) Authorization Header String');

   t.deepEquals(qp, mockQp, '(request token) + (api) query params')
   


})

test('add Query String parametars (access_token leg)', function(t){
   t.plan(5);   
 
  
  var mockQp = { 
     legHost: 'api.twitter.com',
     legPath: '/oauth/access_token',
     legMethod: 'POST',
     legSBS: 'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3D%26oauth_nonce%3Dajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1523528027%26oauth_token%3D%26oauth_verifier%3D%26oauth_version%3D1.0',
     legAH: 'OAuth oauth_consumer_key="", oauth_nonce="ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ", oauth_signature="", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1523528027", oauth_token="", oauth_verifier="", oauth_version="1.0"' 

   }

   oa.OAuthParams('remove', oa.oauth, oa[oa.leg[0]]) // remove callback
   oa.OAuthParams('add', oa.oauth, oa[oa.leg[2]])    // add token and verifier params
  
   oa.setRequestOptions(oa.leg[2]);
   
   oa.oauth.oauth_nonce = "ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ"; // set nonce so it doesnt change 
                                                                        // (needs to be tested with t.equals())
   oa.oauth.oauth_timestamp = '1523528027';                             // set timestamp so it doesnt change

   oa.addQueryParams('leg', oa.leg[2]) // add query params for access token leg

   var qp = oa.options.queryParams;
   
   t.equals(qp.legHost, mockQp.legHost,'(leg) Host');
   t.equals(qp.legPath, mockQp.legPath,'(leg) Path');
   t.equals(qp.legMethod, mockQp.legMethod,'(leg) Method');
   
   // 
   t.equals(qp.legSBS, mockQp.legSBS, '(leg) Signature Base String') 
   t.equals(qp.legAH, mockQp.legAH, '(leg) Authorization Header String')
  
}) 

test('add Query String parametars (access_token plus)', function(t){ // test access token and api params
  t.plan(6);   
 
  
   var mockQp = {               // mocks query params needed for "oauth access token plus" request 
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
  
   oa.OAuthParams('remove', oa.oauth, oa[oa.leg[2]]) // remove  token and verifier params
   oa.OAuthParams('add', oa.oauth, oa.apiCall)       // add callback
  
   oa.setRequestOptions(oa.leg[2]);
   
   oa.oauth.oauth_nonce = "ajdud0QydHRnYU9XeHJ5b29kSGpWdmY2bXAxTTk4VQ"; // set nonce so it doesnt change 
                                                                      // (sbs needs to be tested with t.equals())
   oa.oauth.oauth_timestamp = '1523528027';                           // set timestamp so it doesnt change

   oa.addQueryParams('api', oa.UserOptions) // add query params for access token leg
   
   var qp = oa.options.queryParams

   t.equals(qp.apiHost, mockQp.apiHost, '(api) Host');
   t.equals(qp.apiPath, mockQp.apiPath, '(api) Path');
   t.equals(qp.apiMethod, mockQp.apiMethod, '(api) Method');
   
   t.equals(qp.apiSBS, mockQp.apiSBS, '(api) Signature Base String');
   t.equals(qp.apiAH, mockQp.apiAH, '(api) Authorization Header String');

   t.deepEquals(qp, mockQp, '(access token) + (api) query params')
   
   
}) 



